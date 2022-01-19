import {
    IApplicationContext,
    IPlugin
} from '@znetstar/attic-common/lib/Server';
import { promises as fs } from 'fs';
import {
    IIdentityEntity as
        IIdentityEntityBase
} from "@znetstar/attic-common/lib/IIdentity";

import {
    IAccessToken
} from "@znetstar/attic-common/lib/IAccessToken";

import { GenericError } from '@znetstar/attic-common/lib/Error/GenericError'
import fetch from "node-fetch";
import {IError} from "@znetstar/attic-common/lib/Error/IError";
import {IIdentity} from "@znetstar/attic-common";
import * as URL from 'url';
import * as _ from 'lodash';
import IClient from "@znetstar/attic-common/lib/IClient";

interface IIdentityEntityModel{
    externalId: string;
    otherFields?: any;
}

type IIdentityEntity = IIdentityEntityModel&IIdentityEntityBase&IIdentity;

export class AtticServerTwitter implements IPlugin {
    constructor(public applicationContext: IApplicationContext) {

    }

    public async getTwitterIdentity(accessToken: IAccessToken): Promise<IIdentityEntity> {
        let resp = await fetch(`https://api.twitter.com/2/users/me?user.fields=profile_image_url,id,name,username`, {
            headers: {
                'Authorization': `Bearer ${accessToken.token}`
            }
        });

        let body:  any;
        let e2: any;
        try { body = await resp.json(); }
        catch (err) { e2 = err; }

        if (resp.status !== 200) {
            throw new GenericError(`Could not locate Twitter identity`, 2001, 403, (
                body || e2
            ) as any as IError);
        }

        body = body.data;

        let fields: IIdentityEntity = {
            firstName: body.name?.split(' ')[0] || '',
            lastName: body.name?.split(' ')[1] || '',
            clientName: accessToken.clientName,
            phone: '',
            email: `${body.id}.twitter@${_.get(this, 'applicationContext.config.emailHostname') || process.env.EMAIL_HOSTNAME}`,
            otherFields: body,
            source: {
                href: `https://api.twitter.com/2/users/${body.id}`
            },
            type: 'IdentityEntity',
            client: accessToken.client,
            user: null,
            externalId: body.id,
            id: null,
            _id: null
        };

        if (body.profile_image_url) {
          fields.photo = Buffer.from(await (await fetch(body.profile_image_url)).arrayBuffer());
        }

        return fields;
    }


    public async init(): Promise<void> {
        this.applicationContext.registerHook<IIdentityEntity>(`Client.getIdentityEntity.twitter.provider`, this.getTwitterIdentity);
        this.applicationContext.registerHook<string|void>('AuthMiddleware.auth.twitter.authorize.token', async (opts: { provider: any, params: URL.URLSearchParams, fetchOpts: any }): Promise<string|void> => {
          opts.params.set('code_verifier', 'challenge');
          opts.params.delete('client_secret');
          opts.fetchOpts.headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${Buffer.from(opts.provider.clientId + ':' + opts.provider.clientSecret, 'utf8').toString('base64')}`
          };

        });
      this.applicationContext.registerHook<string|undefined>('Web.AuthMiddleware.auth.twitter.authorize.getAuthorizeRedirectUri', async (opts: any): Promise<string|undefined> => {
        if (opts.provider.authorizeUri) {
          const u = new URL.URL(opts.provider.authorizeUri);

          u.searchParams.set('client_id', opts.provider.clientId);
          // u.searchParams.set('redirect_uri',  opts.newState.redirectUri);
          u.searchParams.set('state', opts.stateKey.split('.').slice(-1)[0]);
          u.searchParams.set('response_type', 'code');
          u.searchParams.set('code_challenge', 'challenge');
          u.searchParams.set('code_challenge_method', 'plain');
          return u.href+'&'+'redirect_uri='+opts.newState.redirectUri+'&scope='+[].concat(opts.provider.scope).join('%20');
        }
      });
    }

    public get name(): string {
        return JSON.parse((require('fs').readFileSync(require('path').join(__dirname, '..', 'package.json'), 'utf8'))).name;
    }
}

export default AtticServerTwitter;
