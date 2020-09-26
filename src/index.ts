import { smrQuery, SMRModVersion } from './smr';
import {
  formatError, setIntervalImmediate,
} from './util';
import { logger } from './logging';
import { verifyVersion } from './verify';

const verifiedVersions: string[] = [];

async function checkForUnverifiedVersions() {
  try {
    const versionQuery = await smrQuery<{
      getUnapprovedVersions: {
        versions: SMRModVersion[]
      }
    }>(`
    query {
      getUnapprovedVersions {
        versions {
          id,
          mod_id,
          version
          link,
        }
      }
    }`);
    const unapprovedVersions = versionQuery.getUnapprovedVersions.versions;

    unapprovedVersions.forEach(async (version) => {
      if (!verifiedVersions.includes(version.id)) {
        verifiedVersions.push(version.id);
        logger.info(`Verifying ${version.mod_id}@${version.version} (${version.id}).`);
        const verifyResult = await verifyVersion(version);
        logger.info(`Result of verifying ${version.mod_id}@${version.version} (${version.id}) is ${verifyResult ? 'ok' : 'bad'}.`);
        if (verifyResult) {
          try {
            const approveQuery = await smrQuery(`
            mutation($versionId: VersionID!) {
              approveVersion(versionId: $versionId)
            }`, { versionId: version.id }) as {
              approveVersion: boolean
            };
            if (!approveQuery.approveVersion) {
              logger.error(`Failed to approve ${version.mod_id}@${version.version} (${version.id}).`);
            }
          } catch (e) {
            logger.error(`Error approving ${version.mod_id}@${version.version} (${version.id}): ${formatError(e)}.`);
          }
        } else {
          logger.info('Version should be checked manually.');
        }
      }
    });
  } catch (e) {
    logger.error(`Error checking for unapproved versions: ${formatError(e)}.`);
  }
}

logger.info('Initialized');
setIntervalImmediate(checkForUnverifiedVersions, 30 * 1000);
