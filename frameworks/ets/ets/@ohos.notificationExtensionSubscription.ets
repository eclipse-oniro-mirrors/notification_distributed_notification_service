/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AsyncCallback, BusinessError } from '@ohos.base';
import { BundleOption } from 'notification.NotificationCommonDef';
import { NotificationExtensionSubscriptionInfo } from 'notification.NotificationExtensionSubscriptionInfo';
import UIAbilityContext from 'application.UIAbilityContext';

type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Error) => void;

const ERROR_OK = 0;
const ERROR_PARAM_INVALID = 401;
const ERROR_INTERNAL_ERROR = 160001;

const rejectInternalError: BusinessError<string> = {code: ERROR_INTERNAL_ERROR, data: "Internal error."};
const callbackInternalError: BusinessError = {code: ERROR_INTERNAL_ERROR, data: undefined};
const successCallbackError: BusinessError = {code: ERROR_OK, data: undefined};

const errorParamInvalid: BusinessError = {code: ERROR_PARAM_INVALID, message: "Invalid parameter"};


export default namespace notificationExtensionSubscription {
    loadLibraryWithPermissionCheck("notificationextensionsubscription_ani.z", "@ohos.notificationExtensionSubscription")

    export native function nativeOpenSubscriptionSettings(context: UIAbilityContext): void;
    export native function nativeSubscribe(info: Array<NotificationExtensionSubscriptionInfo>): void;
    export native function nativeUnsubscribe(): void;
    export native function nativeGetSubscribeInfo(): Array<NotificationExtensionSubscriptionInfo>;
    export native function nativeGetAllSubscriptionBundles(): Array<BundleOption>;
    export native function nativeIsUserGranted(): boolean;
    export native function nativeGetUserGrantedState(targetBundle:BundleOption): boolean
    export native function nativeSetUserGrantedState(targetBundle:BundleOption, enabled:boolean): void
    export native function nativeGetUserGrantedEnableBundles(targetBundle: BundleOption): Array<BundleOption>;
    export native function nativeGetUserGrantedEnableBundlesForSelf(): Array<String>;
    export native function nativeSetUserGrantedBundleState(targetBundle:BundleOption,
        enabledBundles:Array<BundleOption>, enabled:boolean): void;

    function isInvalidParameter(bundle: BundleOption): BusinessError
    {
        let error: BusinessError = successCallbackError
        if (bundle == null) {
            error = errorParamInvalid
            return error;
        }
        if (bundle.bundle == null || bundle.bundle?.length === 0) {
            error = errorParamInvalid
            return error;
        }
        return error;
    }

    export function openSubscriptionSettings(context: UIAbilityContext): Promise<void>
    {
        if (context == undefined || context === null) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((
            resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeOpenSubscriptionSettings(context); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function subscribe(info: Array<NotificationExtensionSubscriptionInfo>): Promise<void>
    {
        let pPromise = new Promise<void>((
            resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeSubscribe(info); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function unsubscribe(): Promise<void>
    {
        let pPromise = new Promise<void>((
            resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeUnsubscribe(); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getSubscribeInfo(): Promise<Array<NotificationExtensionSubscriptionInfo>>
    {
        let pPromise = new Promise<Array<NotificationExtensionSubscriptionInfo>>((
            resolve: ResolveCallback<Array<NotificationExtensionSubscriptionInfo>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<NotificationExtensionSubscriptionInfo> => { 
                return nativeGetSubscribeInfo(); });
            p.then((data: NullishType): void => {
                let infos : Array<NotificationExtensionSubscriptionInfo> = 
                    data as Array<NotificationExtensionSubscriptionInfo>;
                resolve(infos);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getAllSubscriptionBundles(): Promise<Array<BundleOption>>
    {
        let pPromise = new Promise<Array<BundleOption>>(
            (resolve: ResolveCallback<Array<BundleOption>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<BundleOption> => { return nativeGetAllSubscriptionBundles(); });
            p.then((data: NullishType): void => {
                let options : Array<BundleOption> = data as Array<BundleOption>;
                resolve(options);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function isUserGranted(): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeIsUserGranted(); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getUserGrantedState(targetBundle: BundleOption): Promise<boolean> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
            let p = taskpool.execute((): boolean => { return nativeGetUserGrantedState(targetBundle); });
            p.then((data: NullishType): void => {
                let ret : boolean = data as boolean;
                resolve(ret);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setUserGrantedState(targetBundle: BundleOption, enabled: boolean): Promise<void>
    {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeSetUserGrantedState(targetBundle, enabled); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getUserGrantedEnableBundles(targetBundle: BundleOption): Promise<Array<BundleOption>> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<Array<BundleOption>>((resolve: ResolveCallback<Array<BundleOption>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<BundleOption> => { return nativeGetUserGrantedEnableBundles(targetBundle); });
            p.then((data: NullishType): void => {
                let bundles : Array<BundleOption> = data as Array<BundleOption>;
                resolve(bundles);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function getUserGrantedEnableBundles(): Promise<Array<String>> {
        let pPromise = new Promise<Array<String>>((resolve: ResolveCallback<Array<String>>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Array<String> => { return nativeGetUserGrantedEnableBundlesForSelf(); });
            p.then((data: NullishType): void => {
                let bundles : Array<String> = data as Array<String>;
                resolve(bundles);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function setUserGrantedBundleState(targetBundle: BundleOption,
        enabledBundles:Array<BundleOption>, enabled:boolean): Promise<void> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => { return nativeSetUserGrantedBundleState(targetBundle, enabledBundles, enabled); });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }
}
