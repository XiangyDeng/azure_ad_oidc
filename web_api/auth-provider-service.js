"use strict";
/**
 * Copyright (c) 2020 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License-AGPL.txt in the project root for license information.
 */
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthProviderService = void 0;
const inversify_1 = require("inversify");
const gitpod_protocol_1 = require("@gitpod/gitpod-protocol");
const lib_1 = require("@gitpod/gitpod-db/lib");
const config_1 = require("../config");
const uuid_1 = require("uuid");

// todo ---------------------------------------------------------------------------------------------------------------------
const aad_urls_1 = require("../aad/aad-urls");

const github_urls_1 = require("../github/github-urls");
const gitlab_urls_1 = require("../gitlab/gitlab-urls");
const bitbucket_server_urls_1 = require("../bitbucket-server/bitbucket-server-urls");
const bitbucket_urls_1 = require("../bitbucket/bitbucket-urls");
const logging_1 = require("@gitpod/gitpod-protocol/lib/util/logging");
const isReachable = require("is-reachable");
let AuthProviderService = class AuthProviderService {
    constructor() {
        this.toAuthProviderParams = (oap) => (Object.assign(Object.assign({}, oap), { 
            // HINT: host is expected to be lower case
            host: oap.host.toLowerCase(), verified: oap.status === "verified", builtin: false, 
            // hiddenOnDashboard: true, // i.e. show only if it's used
            loginContextMatcher: `https://${oap.host}/`, oauth: Object.assign(Object.assign({}, oap.oauth), { clientId: oap.oauth.clientId || "no", clientSecret: oap.oauth.clientSecret || "no" }) }));
        this.callbackUrl = (host) => {
            const safeHost = host.replace(":", "_");
            const pathname = `/auth/${safeHost}/callback`;
            return this.config.hostUrl.with({ pathname }).toString();
        };
    }
    /**
     * Returns all auth providers.
     */
    getAllAuthProviders(exceptOAuthRevisions = []) {
        return __awaiter(this, void 0, void 0, function* () {
            const all = yield this.authProviderDB.findAll(exceptOAuthRevisions);
            const transformed = all.map(this.toAuthProviderParams.bind(this));
            // as a precaution, let's remove duplicates
            const unique = new Map();
            for (const current of transformed) {
                const duplicate = unique.get(current.host);
                if (duplicate) {
                    logging_1.log.warn(`Duplicate dynamic Auth Provider detected.`, { rawResult: all, duplicate: current.host });
                    continue;
                }
                unique.set(current.host, current);
            }
            return Array.from(unique.values());
        });
    }
    getAllAuthProviderHosts() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.authProviderDB.findAllHosts();
        });
    }
    getAuthProvidersOfUser(user) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield this.authProviderDB.findByUserId(gitpod_protocol_1.User.is(user) ? user.id : user);
            return result;
        });
    }
    deleteAuthProvider(authProvider) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.authProviderDB.delete(authProvider);
        });
    }
    updateAuthProvider(entry) {
        return __awaiter(this, void 0, void 0, function* () {
            let authProvider;
            if ("id" in entry) {
                const { id, ownerId } = entry;
                const existing = (yield this.authProviderDB.findByUserId(ownerId)).find((p) => p.id === id);
                if (!existing) {
                    throw new Error("Provider does not exist.");
                }
                const changed = entry.clientId !== existing.oauth.clientId ||
                    (entry.clientSecret && entry.clientSecret !== existing.oauth.clientSecret);
                if (!changed) {
                    return existing;
                }
                // update config on demand
                const oauth = Object.assign(Object.assign({}, existing.oauth), { clientId: entry.clientId, clientSecret: entry.clientSecret || existing.oauth.clientSecret });
                authProvider = Object.assign(Object.assign({}, existing), { oauth, status: "pending" });
            }
            else {
                const existing = yield this.authProviderDB.findByHost(entry.host);
                if (existing) {
                    throw new Error("Provider for this host already exists.");
                }
                authProvider = this.initializeNewProvider(entry);
            }
            return yield this.authProviderDB.storeAuthProvider(authProvider, true);
        });
    }
    initializeNewProvider(newEntry) {
        const { host, type, clientId, clientSecret } = newEntry;
        let urls;
        switch (type) {
            case "GitHub":
                urls = (0, github_urls_1.oauthUrls)(host);
                break;
            case "GitLab":
                urls = (0, gitlab_urls_1.oauthUrls)(host);
                break;
            case "BitbucketServer":
                urls = (0, bitbucket_server_urls_1.oauthUrls)(host);
                break;
            case "Bitbucket":
                urls = (0, bitbucket_urls_1.oauthUrls)(host);
                break;

                // todo-------------------------------------------------------------------------------
            case "Azure AD":
                urls = (0, aad_urls_1.oauthUrls)(host);
                break;
        }
        
        if (!urls) {
            throw new Error("Unexpected service type.");
        }
        const oauth = Object.assign(Object.assign({}, urls), { callBackUrl: this.callbackUrl(host), clientId: clientId, clientSecret: clientSecret });
        return Object.assign(Object.assign({}, newEntry), { id: (0, uuid_1.v4)(), type,
            oauth, status: "pending" });
    }
    markAsVerified(params) {
        return __awaiter(this, void 0, void 0, function* () {
            const { ownerId, id } = params;
            let ap;
            try {
                let authProviders = yield this.authProviderDB.findByUserId(ownerId);
                if (authProviders.length === 0) {
                    // "no-user" is the magic user id assigned during the initial setup
                    authProviders = yield this.authProviderDB.findByUserId("no-user");
                }
                ap = authProviders.find((p) => p.id === id);
                if (ap) {
                    ap = Object.assign(Object.assign({}, ap), { ownerId: ownerId, status: "verified" });
                    yield this.authProviderDB.storeAuthProvider(ap, true);
                }
                else {
                    logging_1.log.warn("Failed to find the AuthProviderEntry to be activated.", { params, id, ap });
                }
            }
            catch (error) {
                logging_1.log.error("Failed to activate AuthProviderEntry.", { params, id, ap });
            }
        });
    }
    isHostReachable(host) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield isReachable(host, { timeout: 2000 });
        });
    }
};
__decorate([
    (0, inversify_1.inject)(lib_1.AuthProviderEntryDB),
    __metadata("design:type", Object)
], AuthProviderService.prototype, "authProviderDB", void 0);
__decorate([
    (0, inversify_1.inject)(config_1.Config),
    __metadata("design:type", Object)
], AuthProviderService.prototype, "config", void 0);
AuthProviderService = __decorate([
    (0, inversify_1.injectable)()
], AuthProviderService);
exports.AuthProviderService = AuthProviderService;
//# sourceMappingURL=auth-provider-service.js.map