import styles from "./login.module.css";

import type { SubmitEvent } from "react";
import { useEffect, useState } from "react";
import { SiGoogle, SiOpenid } from "@icons-pack/react-simple-icons";

import { api } from "@/api/client";
import { queryClient } from "@/api/query";
import { appPath, basePath } from "@/config";
import type { ExternalAuthProviderMetadata, ProviderKind } from "@/constants";

const getReturnTo = () => {
	if (typeof window === "undefined") return appPath("/");
	const requested = new URLSearchParams(window.location.search).get("returnTo") ?? appPath("/");
	if (!requested.startsWith(`${basePath}/`) || !URL.canParse(requested, window.location.origin)) return appPath("/");

	const url = new URL(requested, window.location.origin);
	return url.origin === window.location.origin && url.pathname.startsWith(`${basePath}/`)
		? `${url.pathname}${url.search}${url.hash}`
		: appPath("/");
};

// The server keeps the reason for a refusal in its own log and only sends a code.
const externalAuthErrors: Record<string, string> = {
	registration_closed: "This account isn't set up yet. Ask an administrator to create it for you.",
	domain_not_allowed: "Your email domain isn't allowed to sign in here.",
	email_not_verified: "Your provider didn't confirm a verified email address.",
	access_denied: "Your account doesn't have access to this instance.",
	groups_incomplete: "Your provider sent an incomplete group list. Ask an administrator to check the group claim.",
	provider_error: "Your provider cancelled the sign-in.",
	state_mismatch: "The sign-in took too long or was interrupted. Please try again.",
	unavailable: "Sign-in is unavailable right now. Please try again later.",
};

const ProviderLogo = ({ kind }: { kind: ProviderKind }) => {
	if (kind === "google") return <SiGoogle color="#4285f4" aria-hidden="true" />;
	if (kind === "microsoft")
		return (
			<svg viewBox="0 0 24 24" aria-hidden="true">
				<path fill="#f25022" d="M1 1h10v10H1z" />
				<path fill="#7fba00" d="M13 1h10v10H13z" />
				<path fill="#00a4ef" d="M1 13h10v10H1z" />
				<path fill="#ffb900" d="M13 13h10v10H13z" />
			</svg>
		);
	return <SiOpenid color="#f78c40" aria-hidden="true" />;
};

export const LoginPage = () => {
	const [providers, setProviders] = useState<ExternalAuthProviderMetadata[]>([]);
	const [error, setError] = useState<string>();
	const [isSubmitting, setIsSubmitting] = useState(false);

	useEffect(() => {
		const code = new URLSearchParams(window.location.search).get("externalAuthError");
		if (code) setError(externalAuthErrors[code] ?? "External sign-in failed. Please try again.");

		let active = true;
		api["/api/dashboard/auth/external"]
			.get()
			.json()
			.then((metadata) => {
				if (active) setProviders(metadata.providers);
			})
			.catch(() => {});
		return () => {
			active = false;
		};
	}, []);

	const handleSubmit = async (event: SubmitEvent<HTMLFormElement>) => {
		event.preventDefault();
		setError(undefined);
		setIsSubmitting(true);

		const { username, password } = Object.fromEntries(new FormData(event.currentTarget)) as {
			username: string;
			password: string;
		};

		try {
			await api["/api/dashboard/auth/login"].post({ json: { username, password } });
			queryClient.clear();
			window.location.href = getReturnTo();
		} catch {
			setError("Invalid username or password");
			setIsSubmitting(false);
		}
	};

	return (
		<section className={styles.page}>
			<h1>Sign in</h1>
			{providers.length > 0 && (
				<div className={styles.providers}>
					{providers.map((provider) => (
						<a
							key={provider.name}
							// The client router would fetch the start route first; each request mints a new state cookie.
							data-astro-reload
							className={`button-secondary ${styles.externalAuth}`}
							href={appPath(
								`/api/dashboard/auth/external/start?${new URLSearchParams({
									provider: provider.name,
									returnTo: getReturnTo(),
								})}`,
							)}
						>
							<span className={styles.providerIcon}>
								<ProviderLogo kind={provider.kind} />
							</span>
							Continue with {provider.displayName}
						</a>
					))}
					<div className={styles.separator}>or</div>
				</div>
			)}
			<form className={styles.form} onSubmit={handleSubmit}>
				<input
					type="text"
					name="username"
					placeholder="Username"
					aria-label="Username"
					autoComplete="username"
					required
				/>
				<input
					type="password"
					name="password"
					placeholder="Password"
					aria-label="Password"
					autoComplete="current-password"
					required
				/>
				<button type="submit" disabled={isSubmitting}>
					{isSubmitting ? "Signing in..." : "Login"}
				</button>
				{error && (
					<article className={styles.error} role="alert" aria-live="assertive">
						{error}
					</article>
				)}
			</form>
		</section>
	);
};
