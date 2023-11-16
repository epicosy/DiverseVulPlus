import json
import pandas as pd
import re
import ast

from pathlib import Path
from typing import List, Union

root_path = Path(__file__).parent
dataset_path = root_path.parent / 'diversevul_20230702.json'

# regex to match CVE IDs
cve_id_pattern = r'CVE-\d{4}-\d{4,7}'


def read_data() -> List[dict]:
    with dataset_path.open(mode='r') as f:
        return [json.loads(line) for line in f.readlines()]


def read_tenet_data() -> pd.DataFrame:
    df = pd.read_csv(str(root_path / 'tenet.csv'), sep=',')
    # drop unnecessary index column 'Unnamed: 0'
    return df.drop(columns=['Unnamed: 0'])


def to_csv(data: List[dict]):
    pd.DataFrame(data).to_csv(str(root_path / 'diverse_vul.csv'), index=False)


def find_cve_id(message: str) -> Union[str, None]:
    match = re.match(cve_id_pattern, message)

    if match:
        return match.group(0)

    return None


def get_df_with_cve_ids() -> pd.DataFrame:
    output_path = root_path / 'diverse_vul_ids.csv'

    if output_path.exists():
        return pd.read_csv(str(output_path))

    # check all files that were created by splitting the dataframe
    chunks = []

    for f in root_path.iterdir():
        if f.is_file() and f.suffix == '.csv' and f.stem.startswith('diverse_vul_ids_'):
            print(f"Reading {f}")
            chunks.append(pd.read_csv(str(f)))

    if len(chunks) > 0:
        return pd.concat(chunks)

    diverse_vul_df = pd.DataFrame(read_data())
    print(f"Number of unique project-commit-id pairs in diversevul dataset: {len(diverse_vul_df.groupby(['project', 'commit_id']))}")
    print(f"Finding CVE IDs in diversevul dataset by matching messages")
    diverse_vul_df['cve_id'] = diverse_vul_df.message.apply(find_cve_id)
    # filter out None values
    diverse_vul_ids_df = diverse_vul_df[diverse_vul_df['cve_id'].notnull()]

    print(f"Finding remaining CVE IDs in diversevul dataset by matching project/commit with tenet dataset")

    tenet_df = read_tenet_data()
    tenet_df.rename(columns={'project': 'project_href'}, inplace=True)
    tenet_df['project'] = tenet_df['project_href'].apply(lambda x: x.split('/')[-1])
    # chain is a string list, so it needs to be converted to a list
    tenet_df['chain'] = tenet_df['chain'].apply(lambda x: ast.literal_eval(x))
    rows_matches = []

    for project, rows in diverse_vul_df[diverse_vul_df['cve_id'].isnull()].groupby('project'):
        for sha, rows2 in rows.groupby('commit_id'):
            project_search = tenet_df[tenet_df['project'] == project]

            if len(project_search) == 0:
                continue

            sha_search = project_search[project_search['last_fix_commit'] == sha]

            if len(sha_search) > 0:
                # check if CVE-ID is unique
                if len(sha_search['vuln_id'].unique()) > 1:
                    print(f"Multiple CVE-IDs for {sha}")
                    continue

                rows2['cve_id'] = sha_search['vuln_id'].values[0]
                rows_matches.append(rows2)
                continue

            chain_search = project_search[project_search['chain'].apply(lambda x: sha in x)]

            if len(chain_search) > 0:
                # check if CVE-ID is unique
                if len(chain_search['vuln_id'].unique()) > 1:
                    print(f"Multiple CVE-IDs for {sha}")
                    continue
                rows2['cve_id'] = chain_search['vuln_id'].values[0]
                rows_matches.append(rows2)

    res_df = pd.concat(rows_matches)
    res_df = pd.concat([res_df, diverse_vul_ids_df])
    print(f"Number of collected CVE IDs: {len(res_df['cve_id'].unique())}")
    size_mbs = res_df.memory_usage(deep=True).sum() / 1024 ** 2
    print(f"Size of the dataframe in MBs: {size_mbs}")

    if size_mbs > 50:
        # split dataframe in chunks of 49MB
        chunks = int(size_mbs / 49) + 1
        print(f"Splitting dataframe in {chunks} chunks")
        res_df = res_df.reset_index(drop=True)
        chunk_size = int(len(res_df) / chunks)
        print(f"Chunk size: {chunk_size}")

        for i in range(chunks):
            print(f"Saving chunk {i}")
            res_df[i * chunk_size:(i + 1) * chunk_size].to_csv(str(root_path / f'diverse_vul_ids_{i}.csv'), index=False)
    else:
        res_df.to_csv(str(root_path / 'diverse_vul_ids.csv'), index=False)

    return res_df


def get_single_short_vulnerable_function_ids(diverse_vul_df: pd.DataFrame) -> pd.DataFrame:
    # get cve_ids with only one vulnerable function
    vul_df = diverse_vul_df[diverse_vul_df['target'] == 1]
    counts = vul_df['cve_id'].value_counts()
    ids = counts[counts == 1].index
    print(f"Number of CVE IDs with only one vulnerable function: {len(ids)}")
    single_vul_df = vul_df[vul_df['cve_id'].isin(ids)]

    # get cve_ids with only one short vulnerable function
    single_vul_sizes = sorted(single_vul_df['size'].value_counts().to_dict().keys())
    # get the average size of vulnerable functions
    mean = sum(single_vul_sizes) / len(single_vul_sizes)
    print(f"Average size of single vulnerable functions: {mean}")
    short_single_vul_df = single_vul_df[single_vul_df['size'] < mean]
    print(f"Number of CVE IDs with only one short vulnerable function: {len(short_single_vul_df)}")

    return short_single_vul_df


if __name__ == '__main__':
    diverse_vul_df = get_df_with_cve_ids()
    unique_ids = diverse_vul_df['cve_id'].unique()
    print(f"Number of unique CVE IDs: {len(unique_ids)}")

    short_single_vul_df = get_single_short_vulnerable_function_ids(diverse_vul_df)
    # merge with tenet dataset
    tenet_df = read_tenet_data()
    merged = short_single_vul_df.merge(tenet_df, left_on='cve_id', right_on='vuln_id')
    print(f"Number of CVE IDs with only one vulnerable function and in tenet dataset: {len(merged)}")
    # include only single patch CVE-IDS
    merged = merged[merged['patch'] == 'SINGLE']
    print(f"Differing commit ids in diversevul/tenet {len(merged[merged['commit_id'] != merged['last_fix_commit']])}")
    print(f"Number of CVE IDs with only one vulnerable function and in tenet dataset and single patch: {len(merged)}")

    merged.to_csv(str(root_path / 'diverse_vul_tenet.csv'), index=False)

