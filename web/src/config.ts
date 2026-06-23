type RuntimeConfig = {
	baseUrl: string;
	disableFavicons: boolean;
	oidcEnabled: boolean;
	oidcButtonLabel: string | null;
};

const readConfig = (): RuntimeConfig | undefined => {
	if (typeof document === "undefined") return undefined;

	const text = document.getElementById("liwan-config")?.textContent;
	if (!text) return undefined;

	try {
		const config = JSON.parse(text) as Partial<RuntimeConfig>;
		if (typeof config.baseUrl === "string" && typeof config.disableFavicons === "boolean") {
			return {
				baseUrl: config.baseUrl,
				disableFavicons: config.disableFavicons,
				oidcEnabled: config.oidcEnabled ?? false,
				oidcButtonLabel: config.oidcButtonLabel ?? null,
			};
		}
	} catch {
		return undefined;
	}

	return undefined;
};
export const runtimeConfig = readConfig();
