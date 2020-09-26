import { performance } from 'perf_hooks';
import { logger } from './logging';
import { smrQuery, SMRModVersion } from './smr';
import { formatError } from './util';
import { verifyVersion } from './verify';

async function test() {
  try {
    const versionQuery = await smrQuery<{
      getMods: {
        mods: {
          versions: SMRModVersion[]
        }[]
      }
    }>(`
    query {
      getMods(filter:{limit: 5, offset: 5}) {
        mods {
          versions(filter:{limit: 5}) {
            id,
            mod_id,
            version
            link,
          }
        }
      }
    }`);
    const { mods } = versionQuery.getMods;
    mods.forEach((mod) => {
      mod.versions.forEach(async (version) => {
        const t1 = performance.now();
        const verifyResult = await verifyVersion(version);
        const t2 = performance.now();
        logger.info(`Result of verifying ${version.mod_id}@${version.version} (${version.id}) is ${verifyResult ? 'ok' : 'bad'}. In ${t2 - t1}ms`);
      });
    });
  } catch (e) {
    logger.error(`Error getting mods for test: ${formatError(e)}.`);
  }
}

test();
