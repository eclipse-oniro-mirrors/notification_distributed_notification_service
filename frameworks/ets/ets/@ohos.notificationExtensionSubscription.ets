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
import { BundleOption, UserGrantSetting } from 'notification.NotificationCommonDef';
import { BundleOption, GrantedBundleInfo } from 'notification.NotificationCommonDef';
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
    native function nativeOpenSubscriptionSettingsWithResult(context: UIAbilityContext): UserGrantSetting;
    native function nativeSubscribe(info: NotificationExtensionSubscriptionInfo[]): Promise<void>;
    native function nativeUnsubscribe(): Promise<void>;
    native function nativeGetSubscribeInfo(): Promise<NotificationExtensionSubscriptionInfo[]>;
    native function nativeGetAllSubscriptionBundles(): Promise<BundleOption[]>;
    native function nativeIsUserGranted(): Promise<boolean>;
    native function nativeGetUserGrantedState(targetBundle:BundleOption): Promise<boolean>;
    native function nativeSetUserGrantedState(targetBundle:BundleOption, enabled:boolean): Promise<void>;
    native function nativeGetUserGrantedEnabledBundles(targetBundle: BundleOption): Promise<BundleOption[]>;
    native function nativeGetUserGrantedEnabledBundlesForSelf(): Promise<GrantedBundleInfo[]>;
    native function nativeSetUserGrantedBundleState(targetBundle: BundleOption,
        enabledBundles:BundleOption[], enabled:boolean): Promise<void>;

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
            p.then((data: Any): void => {
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

    function openSubscriptionSettingsWithResult(context: UIAbilityContext): Promise<UserGrantSetting> {
        if (context == undefined || context === null) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<UserGrantSetting>((resolve: ResolveCallback<UserGrantSetting>, reject: RejectCallback): void => {
            let p = taskpool.execute((): UserGrantSetting => { return nativeOpenSubscriptionSettingsWithResult(context); });
            p.then((data: Any): void => {
                let result: UserGrantSetting = data as UserGrantSetting;
                resolve(result);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    function subscribe(info: NotificationExtensionSubscriptionInfo[]): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeSubscribe(info);
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function unsubscribe(): Promise<void> {
        let result: Promise<void>;
        try {
            result = nativeUnsubscribe();
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function getSubscribeInfo(): Promise<NotificationExtensionSubscriptionInfo[]> {
        let result: Promise<NotificationExtensionSubscriptionInfo[]>;
        try {
            result = nativeGetSubscribeInfo();
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function getAllSubscriptionBundles(): Promise<BundleOption[]> {
        let result: Promise<BundleOption[]>;
        try {
            result = nativeGetAllSubscriptionBundles();
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function isUserGranted(): Promise<boolean> {
        let result: Promise<boolean>;
        try {
            result = nativeIsUserGranted();
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function getUserGrantedState(targetBundle: BundleOption): Promise<boolean> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<boolean>;
        try {
            result = nativeGetUserGrantedState(targetBundle);
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function setUserGrantedState(targetBundle: BundleOption, enabled: boolean): Promise<void> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetUserGrantedState(targetBundle, enabled);
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function getUserGrantedEnabledBundles(targetBundle: BundleOption): Promise<BundleOption[]> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<BundleOption[]>;
        try {
            result = nativeGetUserGrantedEnabledBundles(targetBundle);
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function getUserGrantedEnabledBundles(): Promise<GrantedBundleInfo[]> {
        let result: Promise<GrantedBundleInfo[]>;
        try {
            result = nativeGetUserGrantedEnabledBundlesForSelf();
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }

    function setUserGrantedBundleState(targetBundle: BundleOption,
        enabledBundles: BundleOption[], enabled: boolean): Promise<void> {
        let error: BusinessError = isInvalidParameter(targetBundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        let result: Promise<void>;
        try {
            result = nativeSetUserGrantedBundleState(targetBundle, enabledBundles, enabled);
        } catch (err) {
            let error: BusinessError = err as BusinessError;
            throw error;
        }
        return result;
    }
}
