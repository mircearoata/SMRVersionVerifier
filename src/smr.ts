import got from 'got';
import { SMRAuthorization } from '../config.json';

export const SMR_API_URL = 'https://api.ficsit.app';
const SMR_GQL_URL = `${SMR_API_URL}/v2/query`;

export interface SMRModVersion {
  id: string;
  // eslint-disable-next-line camelcase
  mod_id: string;
  version: string;
  link: string;
}

export async function smrQuery<T>(query: string, variables?: unknown): Promise<T> {
  const result = JSON.parse((await got(SMR_GQL_URL, {
    headers: {
      Authorization: SMRAuthorization,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query,
      variables,
    }),
    method: 'POST',
  })).body);
  if (result.error) {
    throw result.error;
  }
  return result.data as T;
}
