import { createRequire } from "module";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));

const binding = require(join(__dirname, "build/Release/pam.node"));

/**
 * @param {string} username
 * @param {string} password
 * @param {string} [service='login']
 * @returns {Promise<boolean>}
 */
export function authenticate(username, password, service = "login") {
    return binding.authenticate(username, password, service);
}
