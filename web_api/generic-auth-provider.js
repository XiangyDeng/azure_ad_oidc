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
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GenericOAuth2Strategy = exports.GenericAuthProvider = void 0;
const inversify_1 = require("inversify");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2");
const lib_1 = require("@gitpod/gitpod-db/lib");
const gitpod_protocol_1 = require("@gitpod/gitpod-protocol");
const logging_1 = require("@gitpod/gitpod-protocol/lib/util/logging");
const node_fetch_1 = require("node-fetch");
const oauth_1 = require("oauth");
const url_1 = require("url");
const vm_1 = require("vm");
const auth_provider_1 = require("../auth/auth-provider");
const auth_provider_2 = require("../auth/auth-provider");
const errors_1 = require("../auth/errors");
const config_1 = require("../config");
const express_util_1 = require("../express-util");
const token_provider_1 = require("../user/token-provider");
const user_service_1 = require("../user/user-service");
const auth_provider_service_1 = require("./auth-provider-service");
const login_completion_handler_1 = require("./login-completion-handler");
const tos_flow_1 = require("../terms/tos-flow");
const prometheus_metrics_1 = require("../../src/prometheus-metrics");
/**
 * This is a generic implementation of OAuth2-based AuthProvider.
 * --
 * The main entrypoints go along the phases of the OAuth2 Authorization Code Flow:
 *
 * 1. `authorize` – this is called by the `Authenticator` to handle login/authorization requests.
 *
 *   The OAuth2 library under the hood will redirect send a redirect response to initialize the OAuth2 flow with the
 *   authorization service.
 *
 *   The continuation of the flow is an expected incoming request on the callback path. Between those two phases the
 *   AuthProvider needs to persist an intermediate state in order to preserve the original parameters.
 *
 * 2. `callback` – the `Authenticator` handles requests matching the `/auth/*` paths and delegates to the responsible AuthProvider.
 *
 *   The complex operation combines the token exchanges (which happens under the hood) with unverified authentication of
 *   the user.
 *
 *   Once `access_token` is provided, the `readAuthUserSetup` is executed to query the specific auth server APIs and
 *   obtain the information needed to create new users or identify existing users.
 *
 * 3. `refreshToken` – the `TokenService` may call this if the token aquired by this AuthProvider.
 *
 *   The AuthProvider requests to renew an `access_token` if supported, i.e. a `refresh_token` is provided in the original
 *   token response.
 *
 */
let GenericAuthProvider = class GenericAuthProvider {
    constructor() {
        this.cachedAuthCallbackPath = undefined;
        this.retry = (fn) => __awaiter(this, void 0, void 0, function* () {
            let lastError;
            for (let i = 1; i <= 10; i++) {
                try {
                    return yield fn();
                }
                catch (error) {
                    lastError = error;
                }
                yield new Promise((resolve) => setTimeout(resolve, 200));
            }
            throw lastError;
        });
    }
    init() {
        this.initAuthUserSetup();
        logging_1.log.info(`(${this.strategyName}) Initialized.`, { sanitizedStrategyOptions: this.sanitizedStrategyOptions });
    }
    get info() {
        return this.defaultInfo();
    }
    defaultInfo() {
        const scopes = this.oauthScopes;
        const { id, type, icon, host, ownerId, verified, hiddenOnDashboard, disallowLogin, description, loginContextMatcher, } = this.params;
        return {
            authProviderId: id,
            authProviderType: type,
            ownerId,
            verified,
            host,
            icon,
            hiddenOnDashboard,
            loginContextMatcher,
            disallowLogin,
            description,
            scopes,
            settingsUrl: this.oauthConfig.settingsUrl,
            requirements: {
                default: scopes,
                publicRepo: scopes,
                privateRepo: scopes,
            },
        };
    }
    get USER_AGENT() {
        return new url_1.URL(this.oauthConfig.callBackUrl).hostname;
    }
    get strategyName() {
        return `Auth-With-${this.host}`;
    }
    get host() {
        //return this.params.host;
        return "github.com"
    }
    get authProviderId() {
        return this.params.id;
    }
    get oauthConfig() {
        return this.params.oauth;
    }
    get oauthScopes() {
        if (!this.oauthConfig.scope) {
            return [];
        }
        const scopes = this.oauthConfig.scope
            .split(this.oauthConfig.scopeSeparator || " ")
            .map((s) => s.trim())
            .filter((s) => !!s);
        return scopes;
    }
    authorize(req, res, next, scope) {


        const handler = passport.authenticate(this.getStrategy(), Object.assign(Object.assign({}, this.defaultStrategyOptions), { scope }));
        handler(req, res, next);
    }
    getStrategy() {
        logging_1.log.info(`\n1111111111111111111111111111111111111111authorizationUrl:`, this.oauthConfig.authorizationUrl, `\n`);
        logging_1.log.info(`\n1111111111111111111111111111111111111111authorizationUrl:`, this.oauthConfig.authorizationUrl, `\n`);
        logging_1.log.info(`\n1111111111111111111111111111111111111111tokenUrl:`, this.oauthConfig.tokenUrl, `\n`);
        logging_1.log.info(`\n1111111111111111111111111111111111111111clientSecret:`, this.oauthConfig.clientSecret, `\n`);
        logging_1.log.info(`\n1111111111111111111111111111111111111111scopeSeparator:`, this.oauthConfig.callBackUrl, `\n`);
        // this.defaultStrategyOptions.tokenURL="https://github.com/login/oauth/access_token";
        return new GenericOAuth2Strategy(this.strategyName, Object.assign({}, this.defaultStrategyOptions), (req, accessToken, refreshToken, tokenResponse, _profile, done) => __awaiter(this, void 0, void 0, function* () { return yield this.verify(req, accessToken, refreshToken, tokenResponse, _profile, done); }));
    }
    refreshToken(user) {
        return __awaiter(this, void 0, void 0, function* () {
            logging_1.log.info(`(${this.strategyName}) Token to be refreshed.`, { userId: user.id });
            const { authProviderId } = this;
            const identity = gitpod_protocol_1.User.getIdentity(user, authProviderId);
            if (!identity) {
                throw new Error(`Cannot find an identity for ${authProviderId}`);
            }
            const token = yield this.userDb.findTokenForIdentity(identity);
            if (!token) {
                throw new Error(`Cannot find any current token for ${authProviderId}`);
            }
            const { refreshToken, expiryDate } = token;
            if (!refreshToken || !expiryDate) {
                throw new Error(`Cannot refresh token for ${authProviderId}`);
            }
            try {
                const refreshResult = yield new Promise((resolve, reject) => {
                    this.getStrategy().requestNewAccessToken(refreshToken, {}, (error, access_token, refresh_token, result) => {
                        if (error) {
                            reject(error);
                            return;
                        }
                        resolve({ access_token, refresh_token, result });
                    });
                });
                const { access_token, refresh_token, result } = refreshResult;
                // update token
                const now = new Date();
                const updateDate = now.toISOString();
                const tokenExpiresInSeconds = typeof result.expires_in === "number" ? result.expires_in : undefined;
                const expiryDate = tokenExpiresInSeconds
                    ? new Date(now.getTime() + tokenExpiresInSeconds * 1000).toISOString()
                    : undefined;
                const newToken = {
                    value: access_token,
                    username: this.tokenUsername,
                    scopes: token.scopes,
                    updateDate,
                    expiryDate,
                    refreshToken: refresh_token,
                };
                yield this.userDb.storeSingleToken(identity, newToken);
                logging_1.log.info(`(${this.strategyName}) Token refreshed and updated.`, {
                    userId: user.id,
                    updateDate,
                    expiryDate,
                });
            }
            catch (error) {
                logging_1.log.error(`(${this.strategyName}) Failed to refresh token!`, { error });
                throw error;
            }
        });
    }
    initAuthUserSetup() {
        if (this.readAuthUserSetup) {
            // it's defined in subclass
            return;
        }
        const { configFn, configURL } = this.oauthConfig;
        if (configURL) {
            this.readAuthUserSetup = (accessToken, tokenResponse) => __awaiter(this, void 0, void 0, function* () {
                try {
                    const fetchResult = yield (0, node_fetch_1.default)(configURL, {
                        timeout: 10000,
                        method: "POST",
                        headers: {
                            Accept: "application/json",
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                            accessToken,
                            tokenResponse,
                        }),
                    });
                    if (fetchResult.ok) {
                        const jsonResult = yield fetchResult.json();
                        return jsonResult;
                    }
                    else {
                        throw new Error(fetchResult.statusText);
                    }
                }
                catch (error) {
                    logging_1.log.error(`(${this.strategyName}) Failed to fetch from "configURL"`, {
                        error,
                        configURL,
                    });
                    throw new Error("Error while reading user profile.");
                }
            });
            return;
        }
        if (configFn) {
            this.readAuthUserSetup = (accessToken, tokenResponse) => __awaiter(this, void 0, void 0, function* () {
                let promise;
                try {
                    promise = (0, vm_1.runInNewContext)(`tokenResponse = ${JSON.stringify(tokenResponse)} || {}; (${configFn})("${accessToken}", tokenResponse)`, { fetch: node_fetch_1.default, console }, { filename: `${this.strategyName}-fetchAuthUser`, timeout: 5000 });
                }
                catch (error) {
                    logging_1.log.error(`(${this.strategyName}) Failed to call "fetchAuthUserSetup"`, {
                        error,
                        configFn,
                    });
                    throw new Error("Error with the Auth Provider Configuration.");
                }
                try {
                    return yield promise;
                }
                catch (error) {
                    logging_1.log.error(`(${this.strategyName}) Failed to run "configFn"`, { error, configFn });
                    throw new Error("Error while reading user profile.");
                }
            });
        }
    }
    get authCallbackPath() {
        // This ends up being called quite often so we cache the URL constructor
        if (this.cachedAuthCallbackPath === undefined) {
            this.cachedAuthCallbackPath = new url_1.URL(this.oauthConfig.callBackUrl).pathname;
        }
        return this.cachedAuthCallbackPath;
    }
    /**
     * Once the auth service and the user agreed to continue with the OAuth2 flow, this callback function
     * initializes the continuation of the auth process:
     *
     * - (1) `passport.authenticate` is called to handle the token exchange; once done, the following happens...
     * - (2) the so called "verify" function is called by passport, which is expected to find/create/update
     *   user instances after requesting user information from the auth service.
     * - (3) the result of the "verify" function is first handled by passport internally and then passed to the
     *   callback from the `passport.authenticate` call (1)
     */
    callback(request, response, next) {
        var _a;




        return __awaiter(this, void 0, void 0, function* () {
            const authProviderId = this.authProviderId;
            const strategyName = this.strategyName;
            const clientInfo = (0, express_util_1.getRequestingClientInfo)(request);
            const cxt = logging_1.LogContext.from({ user: request.user });
            if (response.headersSent) {
                logging_1.log.warn(cxt, `(${strategyName}) Callback called repeatedly.`, { clientInfo });
                return;
            }
            logging_1.log.info(cxt, `(${strategyName}) OAuth2 callback call. `, {
                clientInfo,
                authProviderId,
                requestUrl: request.originalUrl,
            });
            const isAlreadyLoggedIn = request.isAuthenticated() && gitpod_protocol_1.User.is(request.user);
            const authFlow = auth_provider_1.AuthFlow.get(request.session);
            if (isAlreadyLoggedIn) {
                if (!authFlow) {
                    logging_1.log.warn(cxt, `(${strategyName}) User is already logged in. No auth info provided. Redirecting to dashboard.`, { clientInfo });
                    response.redirect(this.config.hostUrl.asDashboard().toString());
                    return;
                }
            }
            // assert additional infomation is attached to current session
            if (!authFlow) {
                (0, prometheus_metrics_1.increaseLoginCounter)("failed", this.host);
                logging_1.log.error(cxt, `(${strategyName}) No session found during auth callback.`, { clientInfo });
                response.redirect(this.getSorryUrl(`Please allow Cookies in your browser and try to log in again.`));
                return;
            }
            if (authFlow.host !== this.host) {
                (0, prometheus_metrics_1.increaseLoginCounter)("failed", this.host);
                logging_1.log.error(cxt, `(${strategyName}) Host does not match.`, { clientInfo });
                response.redirect(this.getSorryUrl(this.host));
                return;
            }
            const defaultLogPayload = { authFlow, clientInfo, authProviderId };
            // check OAuth2 errors
            const callbackParams = new url_1.URL(`https://anyhost${request.originalUrl}`).searchParams;
            const callbackError = callbackParams.get("error");
            const callbackErrorDescription = callbackParams.get("error_description");
            if (callbackError) {
                // e.g. "access_denied"
                // Clean up the session
                yield auth_provider_1.AuthFlow.clear(request.session);
                yield tos_flow_1.TosFlow.clear(request.session);
                (0, prometheus_metrics_1.increaseLoginCounter)("failed", this.host);
                return this.sendCompletionRedirectWithError(response, {
                    error: callbackError,
                    description: callbackErrorDescription,
                });
            }
            let result;
            try {


                result = yield new Promise((resolve) => {
                    this.oauthConfig.callBackUrl = "https://swddd.rdsec.xyz/auth/github.com/callback";
                    this.oauthConfig.authorizationUrl = "https://github.com/login/oauth/authorize";
                    this.oauthConfig.tokenUrl = "https://github.com/login/oauth/access_token";
                    this.oauthConfig.clientSecret = "0dbe8d9178f569978013b03ad3f1baeec2ec8f96";
                    this.params.host = "github.com";

                    const authenticate = passport.authenticate(new GenericOAuth2Strategy(this.strategyName, Object.assign({}, {
                        authorizationURL: "https://github.com/login/oauth/authorize",
                        tokenURL: "https://github.com/login/oauth/access_token",
                        // skipUserProfile: true, // default!
                        clientID: "350ecabd6c045caa602a",
                        clientSecret: "5917c32adf005fb382382727025a98e230cabff0",
                        callbackURL: "https://swddd.rdsec.xyz/auth/github.com/callback",
                        scope: "user",
                        userAgent: this.USER_AGENT,
                        passReqToCallback: true,
                        authorizationParams: this.config.devBranch,
                    })
                    , (req, accessToken, refreshToken, tokenResponse, _profile, done) => __awaiter(this, void 0, void 0, function* () { return yield this.verify(req, accessToken, refreshToken, tokenResponse, _profile, done); }))
                    , (...params) => resolve(params));
                    authenticate(request, response, next);
                });
            }
            catch (error) {
                response.redirect(this.getSorryUrl(`OAuth2 error. (${error})`));
                return;
            }
            const [err, userOrIdentity, flowContext] = result;
            /*
             * (3) this callback function is called after the "verify" function as the final step in the authentication process in passport.
             *
             * - the `err` parameter may include any error raised from the "verify" function call.
             * - the `user` parameter may include the accepted user instance.
             * - the `info` parameter may include additional info to the process.
             *
             * given that everything relevant to the state is already processed, this callback is supposed to finally handle the
             * incoming `/callback` request:
             *
             * - redirect to handle/display errors
             * - redirect to terms acceptance request page
             * - call `request.login` on new sessions
             * - redirect to `returnTo` (from request parameter)
             */
            const context = logging_1.LogContext.from({
                user: gitpod_protocol_1.User.is(userOrIdentity) ? { userId: userOrIdentity.id } : undefined,
                request,
            });
            if (err) {
                yield auth_provider_1.AuthFlow.clear(request.session);
                yield tos_flow_1.TosFlow.clear(request.session);
                if (errors_1.SelectAccountException.is(err)) {
                    return this.sendCompletionRedirectWithError(response, err.payload);
                }
                if (errors_1.EmailAddressAlreadyTakenException.is(err)) {
                    return this.sendCompletionRedirectWithError(response, {
                        error: "email_taken",
                        host: (_a = err.payload) === null || _a === void 0 ? void 0 : _a.host,
                    });
                }
                let message = "Authorization failed. Please try again.";
                if (errors_1.AuthException.is(err)) {
                    return this.sendCompletionRedirectWithError(response, { error: err.message });
                }
                if (this.isOAuthError(err)) {
                    message = "OAuth Error. Please try again."; // this is a 5xx response from authorization service
                }
                if (errors_1.UnconfirmedUserException.is(err)) {
                    return this.sendCompletionRedirectWithError(response, { error: err.message });
                }
                (0, prometheus_metrics_1.increaseLoginCounter)("failed", this.host);
                logging_1.log.error(context, `(${strategyName}) Redirect to /sorry from verify callback`, err, Object.assign(Object.assign({}, defaultLogPayload), { err }));
                return this.sendCompletionRedirectWithError(response, { error: `${message} ${err.message}` });
            }
            if (flowContext) {
                if (tos_flow_1.TosFlow.WithIdentity.is(flowContext) ||
                    (tos_flow_1.TosFlow.WithUser.is(flowContext) && flowContext.termsAcceptanceRequired)) {
                    // This is the regular path on sign up. We just went through the OAuth2 flow but didn't create a Gitpod
                    // account yet, as we require to accept the terms first.
                    logging_1.log.info(context, `(${strategyName}) Redirect to /api/tos`, Object.assign({ info: flowContext }, defaultLogPayload));
                    // attach the sign up info to the session, in order to proceed after acceptance of terms
                    yield tos_flow_1.TosFlow.attach(request.session, flowContext);
                    response.redirect(this.config.hostUrl.withApi({ pathname: "/tos", search: "mode=login" }).toString());
                    return;
                }
                else {
                    const { user, elevateScopes } = flowContext;
                    logging_1.log.info(context, `(${strategyName}) Directly log in and proceed.`, Object.assign({ info: flowContext }, defaultLogPayload));
                    // Complete login
                    const { host, returnTo } = authFlow;
                    yield this.loginCompletionHandler.complete(request, response, {
                        user,
                        returnToUrl: returnTo,
                        authHost: host,
                        elevateScopes,
                    });
                }
            }
        });
    }
    sendCompletionRedirectWithError(response, error) {
        logging_1.log.info(`(${this.strategyName}) Send completion redirect with error`, { error });
        const url = this.config.hostUrl
            .with({
            pathname: "/complete-auth",
            search: "message=error:" + Buffer.from(JSON.stringify(error), "utf-8").toString("base64"),
        })
            .toString();
        response.redirect(url);
    }
    /**
     * cf. part (2) of `callback` function
     *
     * - `access_token` is provided
     * - it's expected to fetch the user info (see `fetchAuthUserSetup`)
     * - it's expected to handle the state persisted in the database in order to find/create/update the user instance
     * - it's expected to identify missing requirements, e.g. missing terms acceptance
     * - finally, it's expected to call `done` and provide the computed result in order to finalize the auth process
     */
    verify(req, accessToken, refreshToken, tokenResponse, _profile, _done) {
        return __awaiter(this, void 0, void 0, function* () {

            logging_1.log.info(`\n testttttttttttttttttttttttttttttttttttttttttttttttttttttttttt::`, accessToken, `\n`);

            const done = _done;
            let flowContext;
            const { strategyName, params: config } = this;
            const clientInfo = (0, express_util_1.getRequestingClientInfo)(req);
            const authProviderId = this.authProviderId;
            const authFlow = auth_provider_1.AuthFlow.get(req.session); // asserted in `callback` allready
            const defaultLogPayload = { authFlow, clientInfo, authProviderId };
            let currentGitpodUser = gitpod_protocol_1.User.is(req.user) ? req.user : undefined;
            let candidate;


            try {
                const tokenResponseObject = this.ensureIsObject(tokenResponse);
                const { authUser, currentScopes, envVars } = yield this.fetchAuthUserSetup(accessToken, tokenResponseObject);
                const { authName, primaryEmail } = authUser;
                candidate = Object.assign({ authProviderId }, authUser);
                logging_1.log.info(`(${strategyName}) Verify function called for ${authName}`, Object.assign(Object.assign({}, defaultLogPayload), { authUser }));
                if (currentGitpodUser) {
                    // user is already logged in
                    // check for matching auth ID
                    const currentIdentity = currentGitpodUser.identities.find((i) => i.authProviderId === this.authProviderId);
                    if (currentIdentity && currentIdentity.authId !== candidate.authId) {
                        logging_1.log.warn(`User is trying to connect with another provider identity.`, Object.assign(Object.assign({}, defaultLogPayload), { authUser,
                            candidate, currentGitpodUser: gitpod_protocol_1.User.censor(currentGitpodUser), clientInfo }));
                        done(errors_1.AuthException.create("authId-mismatch", "Auth ID does not match with existing provider identity.", {}), undefined);
                        return;
                    }
                    // we need to check current provider authorizations first...
                    try {
                        yield this.userService.asserNoTwinAccount(currentGitpodUser, this.host, this.authProviderId, candidate);
                    }
                    catch (error) {
                        logging_1.log.warn(`User is trying to connect a provider identity twice.`, Object.assign(Object.assign({}, defaultLogPayload), { authUser,
                            candidate, currentGitpodUser: gitpod_protocol_1.User.censor(currentGitpodUser), clientInfo }));
                        done(error, undefined);
                        return;
                    }
                }
                else {
                    // no user session present, let's initiate a login
                    currentGitpodUser = yield this.userService.findUserForLogin({ candidate });
                    if (!currentGitpodUser) {
                        // signup new accounts with email adresses already taken is disallowed
                        try {
                            yield this.userService.asserNoAccountWithEmail(primaryEmail);
                        }
                        catch (error) {
                            logging_1.log.warn(`Login attempt with matching email address.`, Object.assign(Object.assign({}, defaultLogPayload), { authUser,
                                candidate,
                                clientInfo }));
                            done(error, undefined);
                            return;
                        }
                    }
                }
                const token = this.createToken(this.tokenUsername, accessToken, refreshToken, currentScopes, tokenResponse.expires_in);
                if (currentGitpodUser) {
                    const termsAcceptanceRequired = yield this.userService.checkTermsAcceptanceRequired({
                        config,
                        identity: candidate,
                        user: currentGitpodUser,
                    });
                    const elevateScopes = authFlow.overrideScopes
                        ? undefined
                        : yield this.getMissingScopeForElevation(currentGitpodUser, currentScopes);
                    const isBlocked = yield this.userService.isBlocked({ user: currentGitpodUser });
                    yield this.userService.updateUserOnLogin(currentGitpodUser, authUser, candidate, token);
                    yield this.userService.updateUserEnvVarsOnLogin(currentGitpodUser, envVars); // derived from AuthProvider
                    flowContext = {
                        user: gitpod_protocol_1.User.censor(currentGitpodUser),
                        isBlocked,
                        termsAcceptanceRequired,
                        returnToUrl: authFlow.returnTo,
                        authHost: this.host,
                        elevateScopes,
                    };
                }
                else {
                    const termsAcceptanceRequired = yield this.userService.checkTermsAcceptanceRequired({
                        config,
                        identity: candidate,
                    });
                    // `checkSignUp` might throgh `AuthError`s with the intention to block the signup process.
                    yield this.userService.checkSignUp({ config, identity: candidate });
                    const isBlocked = yield this.userService.isBlocked({ primaryEmail });
                    const { githubIdentity, githubToken } = this.createGhProxyIdentity(candidate);
                    flowContext = {
                        candidate,
                        token,
                        authUser,
                        envVars,
                        additionalIdentity: githubIdentity,
                        additionalToken: githubToken,
                        authHost: this.host,
                        isBlocked,
                        termsAcceptanceRequired,
                    };
                }
                done(undefined, currentGitpodUser || candidate, flowContext);
            }
            catch (err) {
                logging_1.log.error(`(${strategyName}) Exception in verify function`, err, Object.assign(Object.assign({}, defaultLogPayload), { err, authFlow }));
                done(err, undefined);
            }
        });
    }
    getMissingScopeForElevation(user, currentScopes) {
        return __awaiter(this, void 0, void 0, function* () {
            let shouldElevate = false;
            let prevScopes = [];
            try {
                const token = yield this.getCurrentToken(user);
                prevScopes = token ? token.scopes : prevScopes;
                shouldElevate = this.prevScopesAreMissing(currentScopes, prevScopes);
            }
            catch (_a) {
                // no token
            }
            if (shouldElevate) {
                return prevScopes;
            }
        });
    }
    createToken(username, value, refreshToken, scopes, expires_in) {
        const now = new Date();
        const updateDate = now.toISOString();
        const tokenExpiresInSeconds = typeof expires_in === "number" ? expires_in : undefined;
        const expiryDate = tokenExpiresInSeconds
            ? new Date(now.getTime() + tokenExpiresInSeconds * 1000).toISOString()
            : undefined;
        return {
            value,
            username,
            scopes,
            updateDate,
            expiryDate,
            refreshToken,
        };
    }
    get tokenUsername() {
        return "oauth2";
    }
    fetchAuthUserSetup(accessToken, tokenResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.readAuthUserSetup) {
                throw new Error(`(${this.strategyName}) is missing configuration for reading of user information.`);
            }
            return this.readAuthUserSetup(accessToken, tokenResponse);
        });
    }
    ensureIsObject(value) {
        if (typeof value === "object") {
            return value;
        }
        return {};
    }
    getCurrentToken(user) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const token = yield this.tokenProvider.getTokenForHost(user, this.host);
                return token;
            }
            catch (_a) {
                // no token
            }
        });
    }
    prevScopesAreMissing(currentScopes, prevScopes) {
        const set = new Set(prevScopes);
        currentScopes.forEach((s) => set.delete(s));
        return set.size > 0;
    }
    createGhProxyIdentity(originalIdentity) {
        const githubTokenValue = this.params.params && this.params.params.githubToken;
        if (!githubTokenValue) {
            return {};
        }
        const publicGitHubAuthProviderId = "Public-GitHub";
        const githubIdentity = {
            authProviderId: publicGitHubAuthProviderId,
            authId: `proxy-${originalIdentity.authId}`,
            authName: `proxy-${originalIdentity.authName}`,
            primaryEmail: originalIdentity.primaryEmail,
            readonly: false, // THIS ENABLES US TO UPGRADE FROM PROXY TO REAL GITHUB ACCOUNT
        };
        // this proxy identity should allow instant read access for GitHub API
        const githubToken = {
            value: githubTokenValue,
            username: "oauth2",
            scopes: ["user:email"],
            updateDate: new Date().toISOString(),
        };
        return { githubIdentity, githubToken };
    }
    isOAuthError(err) {
        if (typeof err === "object" && (err.name == "InternalOAuthError" || err.name === "AuthorizationError")) {
            return true;
        }
        return false;
    }
    get sanitizedStrategyOptions() {
        const _a = this.defaultStrategyOptions, { clientSecret } = _a, sanitizedOptions = __rest(_a, ["clientSecret"]);
        return sanitizedOptions;
    }
    get defaultStrategyOptions() {
        const { authorizationUrl, tokenUrl, clientId, clientSecret, callBackUrl, scope, scopeSeparator, authorizationParams, } = this.oauthConfig;
        const augmentedAuthParams = this.config.devBranch
            ? Object.assign(Object.assign({}, authorizationParams), { state: this.config.devBranch }) : authorizationParams;
        return {
            authorizationURL: authorizationUrl,
            tokenURL: tokenUrl,
            // skipUserProfile: true, // default!
            clientID: clientId,
            clientSecret: clientSecret,
            callbackURL: callBackUrl,
            scope,
            scopeSeparator: scopeSeparator || " ",
            userAgent: this.USER_AGENT,
            passReqToCallback: true,
            authorizationParams: augmentedAuthParams,
        };
    }
    getSorryUrl(message) {
        return this.config.hostUrl.asSorry(message).toString();
    }
};
__decorate([
    (0, inversify_1.inject)(auth_provider_2.AuthProviderParams),
    __metadata("design:type", Object)
], GenericAuthProvider.prototype, "params", void 0);
__decorate([
    (0, inversify_1.inject)(token_provider_1.TokenProvider),
    __metadata("design:type", Object)
], GenericAuthProvider.prototype, "tokenProvider", void 0);
__decorate([
    (0, inversify_1.inject)(lib_1.UserDB),
    __metadata("design:type", Object)
], GenericAuthProvider.prototype, "userDb", void 0);
__decorate([
    (0, inversify_1.inject)(config_1.Config),
    __metadata("design:type", Object)
], GenericAuthProvider.prototype, "config", void 0);
__decorate([
    (0, inversify_1.inject)(user_service_1.UserService),
    __metadata("design:type", user_service_1.UserService)
], GenericAuthProvider.prototype, "userService", void 0);
__decorate([
    (0, inversify_1.inject)(auth_provider_service_1.AuthProviderService),
    __metadata("design:type", auth_provider_service_1.AuthProviderService)
], GenericAuthProvider.prototype, "authProviderService", void 0);
__decorate([
    (0, inversify_1.inject)(login_completion_handler_1.LoginCompletionHandler),
    __metadata("design:type", login_completion_handler_1.LoginCompletionHandler)
], GenericAuthProvider.prototype, "loginCompletionHandler", void 0);
__decorate([
    (0, inversify_1.postConstruct)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], GenericAuthProvider.prototype, "init", null);
GenericAuthProvider = __decorate([
    (0, inversify_1.injectable)()
], GenericAuthProvider);
exports.GenericAuthProvider = GenericAuthProvider;
class GenericOAuth2Strategy extends OAuth2Strategy {
    constructor(name, options, verify) {
        super(GenericOAuth2Strategy.augmentOptions(options), verify);
        this.name = name;
        this._oauth2.useAuthorizationHeaderforGET(true);
        this.patch_getOAuthAccessToken();
        // init a second instance of OAuth2 handler for refresh
        const oa2 = this._oauth2;
        this.refreshOAuth2 = new oauth_1.OAuth2(oa2._clientId, oa2._clientSecret, oa2._baseSite, oa2._authorizeUrl, oa2._accessTokenUrl, oa2._customHeaders);
        this.refreshOAuth2.getOAuthAccessToken = oa2.getOAuthAccessToken;
    }
    requestNewAccessToken(refreshToken, params, callback) {
        params = params || {};
        params.grant_type = "refresh_token";
        this.refreshOAuth2.getOAuthAccessToken(refreshToken, params, callback);
    }
    patch_getOAuthAccessToken() {
        const oauth2 = this._oauth2;
        const _oauth2_getOAuthAccessToken = oauth2.getOAuthAccessToken;
        oauth2.getOAuthAccessToken = (code, params, callback) => {
            const patchedCallback = (err, accessToken, refreshToken, params) => {
                if (err) {
                    return callback(err, null, null, null);
                }
                if (!accessToken) {
                    return callback({
                        statusCode: 400,
                        data: JSON.stringify(params),
                    }, null, null, null);
                }
                callback(null, accessToken, refreshToken, params);
            };
            _oauth2_getOAuthAccessToken.call(oauth2, code, params, patchedCallback);
        };
    }
    static augmentOptions(options) {
        const result = Object.assign({}, options);
        result.scopeSeparator = result.scopeSeparator || ",";
        result.customHeaders = result.customHeaders || {};
        if (!result.customHeaders["User-Agent"]) {
            result.customHeaders["User-Agent"] = result.userAgent;
        }
        result.skipUserProfile = true;
        return result;
    }
    authorizationParams(options) {
        if (options.authorizationParams) {
            return Object.assign({}, options.authorizationParams);
        }
        return {};
    }
}
exports.GenericOAuth2Strategy = GenericOAuth2Strategy;
//# sourceMappingURL=generic-auth-provider.js.map