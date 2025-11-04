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

    export enum SubscribeType {
        BLUETOOTH = 0
    }

    native function nativeOpenSubscriptionSettings(context: UIAbilityContext): Promise<int>;
    native function nativeSubscribe(info: NotificationExtensionSubscriptionInfo[]): void;
    native function nativeUnsubscribe(): void;
    native function nativeGetSubscribeInfo(): NotificationExtensionSubscriptionInfo[];
    native function nativeGetAllSubscriptionBundles(): BundleOption[];
    native function nativeIsUserGranted(): boolean;
    native function nativeGetUserGrantedState(targetBundle:BundleOption): boolean
    native function nativeSetUserGrantedState(targetBundle:BundleOption, enabled:boolean): void
    native function nativeGetUserGrantedEnabledBundles(targetBundle: BundleOption): BundleOption[];
    native function nativeGetUserGrantedEnabledBundlesForSelf(): string[];
    native function nativeSetUserGrantedBundleState(targetBundle:BundleOption,
        enabledBundles:BundleOption[], enabled:boolean): void;

    function isInvalidParameter(bundle: BundleOption): BusinessError
    {
        let error: BusinessError = successCallbackError
        if (bundle == null) {
            error = errorParamInvalid
            return error;
        }
        if (bundle.bundle == null) {
            error = errorParamInvalid
            return error;
        }
        return error;
    }

    function openSubscriptionSettings(context: UIAbilityContext): Promise<void> {
        if (context == undefined || context === null) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Promise<int> => { return nativeOpenSubscriptionSettings(context); });
            p.then((data: NullishType): void => {
                if (data == undefined) {
                    reject(rejectInternalError);
                } else {
                    let result: int = data as int;
                    if (result == 0) {
                        resolve(undefined);
                    } else {
                        reject(rejectInternalError);
                    }
                }
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    function subscribe(info: NotificationExtensionSubscriptionInfo[]): Promise<void> {
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

    function unsubscribe(): Promise<void> {
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

    function getSubscribeInfo(): Promise<NotificationExtensionSubscriptionInfo[]> {
        let pPromise = new Promise<NotificationExtensionSubscriptionInfo[]>((
            resolve: ResolveCallback<NotificationExtensionSubscriptionInfo[]>, reject: RejectCallback): void => {
            let p = taskpool.execute((): NotificationExtensionSubscriptionInfo[] => { 
                return nativeGetSubscribeInfo(); });
            p.then((data: NullishType): void => {
                let infos : NotificationExtensionSubscriptionInfo[] = 
                    data as NotificationExtensionSubscriptionInfo[];
                resolve(infos);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    function getAllSubscriptionBundles(): Promise<BundleOption[]> {
        let pPromise = new Promise<BundleOption[]>(
            (resolve: ResolveCallback<BundleOption[]>, reject: RejectCallback): void => {
            let p = taskpool.execute((): BundleOption[] => { return nativeGetAllSubscriptionBundles(); });
            p.then((data: NullishType): void => {
                let options : BundleOption[] = data as BundleOption[];
                resolve(options);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    function isUserGranted(): Promise<boolean> {
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

    function getUserGrantedState(targetBundle: BundleOption): Promise<boolean> {
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

    function setUserGrantedState(targetBundle: BundleOption, enabled: boolean): Promise<void> {
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

    function getUserGrantedEnabledBundles(targetBundle: BundleOption): Promise<BundleOption[]> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let pPromise = new Promise<BundleOption[]>((resolve: ResolveCallback<BundleOption[]>, reject: RejectCallback): void => {
            let p = taskpool.execute((): BundleOption[] => { return nativeGetUserGrantedEnabledBundles(targetBundle); });
            p.then((data: NullishType): void => {
                let bundles : BundleOption[] = data as BundleOption[];
                resolve(bundles);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    function getUserGrantedEnabledBundles(): Promise<string[]> {
        let pPromise = new Promise<string[]>((resolve: ResolveCallback<string[]>, reject: RejectCallback): void => {
            let p = taskpool.execute((): string[] => { return nativeGetUserGrantedEnabledBundlesForSelf(); });
            p.then((data: NullishType): void => {
                let bundles : string[] = data as string[];
                resolve(bundles);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    function setUserGrantedBundleState(targetBundle: BundleOption,
        enabledBundles: BundleOption[], enabled: boolean): Promise<void> {
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
