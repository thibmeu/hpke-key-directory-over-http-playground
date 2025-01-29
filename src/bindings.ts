export type Env = {
    DIRECTORY_CACHE_MAX_AGE_SECONDS: string;
    KEY_NOT_BEFORE_DELAY_IN_MS: string;
	KEYS: R2Bucket;
    MINIMUM_FRESHEST_KEYS: string;
	ROTATION: Workflow;
};