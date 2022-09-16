"use strict";
/**
 * Copyright (c) 2020 Gitpod GmbH. All rights reserved.
 * Licensed under the GNU Affero General Public License (AGPL).
 * See License-AGPL.txt in the project root for license information.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.oauthUrls = void 0;
function oauthUrls(host) {
    return {
        authorizationUrl: `https://swddd.b2clogin.com/swddd.onmicrosoft.com/b2c_1_susi/oauth2/v2.0/authorize`,
        tokenUrl: `https://${host}/login/oauth/access_token`,
    };
}
exports.oauthUrls = oauthUrls;
//# sourceMappingURL=github-urls.js.map