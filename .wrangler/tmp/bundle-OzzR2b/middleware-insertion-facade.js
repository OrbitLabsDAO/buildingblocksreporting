				import worker, * as OTHER_EXPORTS from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/.wrangler/tmp/pages-eR0zqi/functionsWorker-0.3292103618518394.mjs";
				import * as __MIDDLEWARE_0__ from "/Users/cryptoskillz/.npm/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts";
				const envWrappers = [__MIDDLEWARE_0__.wrap].filter(Boolean);
				const facade = {
					...worker,
					envWrappers,
					middleware: [
						__MIDDLEWARE_0__.default,
            ...(worker.middleware ? worker.middleware : []),
					].filter(Boolean)
				}
				export * from "/Users/cryptoskillz/Documents/code/orbitlabs/buildingblock/admin/.wrangler/tmp/pages-eR0zqi/functionsWorker-0.3292103618518394.mjs";

				const maskDurableObjectDefinition = (cls) =>
					class extends cls {
						constructor(state, env) {
							let wrappedEnv = env
							for (const wrapFn of envWrappers) {
								wrappedEnv = wrapFn(wrappedEnv)
							}
							super(state, wrappedEnv);
						}
					};
				

				export default facade;