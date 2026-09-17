# GITHUB ROLLBACK

If upload/PR needs to be abandoned:

1. close the Pull Request without merge;
2. delete the proposal branch;
3. retain the previously frozen local candidate for evidence;
4. do not alter Railway, staging, DB, migration, deploy or production;
5. if any file changed after upload, treat it as a new candidate and recompute all hashes.

There is no runtime rollback because this GitHub gate does not authorize runtime writes.
