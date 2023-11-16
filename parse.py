import json
import pandas as pd
import re

from pathlib import Path
from typing import List, Union

root_path = Path(__file__).parent
dataset_path = root_path.parent / 'diversevul_20230702.json'

# regex to match CVE IDs
cve_id_pattern = r'CVE-\d{4}-\d{4,7}'


def read_data() -> List[dict]:
    with dataset_path.open(mode='r') as f:
        return [json.loads(line) for line in f.readlines()]


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

    full_df = pd.DataFrame(read_data())
    full_df['cve_id'] = full_df.message.apply(find_cve_id)
    # filter out None values
    ids_df = full_df[full_df['cve_id'].notnull()]
    ids_df.to_csv(str(root_path / 'diverse_vul_ids.csv'), index=False)

    return ids_df


if __name__ == '__main__':
    diverse_vul_df = get_df_with_cve_ids()
    unique_ids = diverse_vul_df['cve_id'].unique()
    print(f"Number of unique CVE IDs: {len(unique_ids)}")

    # get cve_ids with only one vulnerable function
    vul_df = diverse_vul_df[diverse_vul_df['target'] == 1]
    counts = vul_df['cve_id'].value_counts()
    ids = counts[counts == 1].index
    print(f"Number of CVE IDs with only one vulnerable function: {len(ids)}")
    single_vul_df = vul_df[vul_df['cve_id'].isin(ids)]

    # get cve_ids with only one short vulnerable function
    # get the average size of vulnerable functions

    single_vul_sizes = sorted(single_vul_df['size'].value_counts().to_dict().keys())
    mean = sum(single_vul_sizes) / len(single_vul_sizes)
    print(f"Average size of single vulnerable functions: {mean}")
    short_single_vul_df = single_vul_df[single_vul_df['size'] < mean]

    # merge with tenet dataset
    tenet_df = pd.read_csv(str(root_path / 'tenet.csv'), sep=',')
    merged = short_single_vul_df.merge(tenet_df, left_on='cve_id', right_on='vuln_id')
    print(f"Number of CVE IDs with only one vulnerable function and in tenet dataset: {len(merged)}")
    merged.to_csv(str(root_path / 'diverse_vul_tenet.csv'), index=False)

