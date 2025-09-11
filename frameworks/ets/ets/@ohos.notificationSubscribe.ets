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
import { NotificationSubscribeInfo } from 'notification.notificationSubscribeInfo';
import { NotificationSubscriber } from 'notification.notificationSubscriber';

type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Error) => void;

const ERROR_OK = 0;
const ERROR_PARAM_INVALID = 401;
const ERROR_INTERNAL_ERROR = 160001;

const rejectInternalError: BusinessError<string> = {code: ERROR_INTERNAL_ERROR, data: "Internal error."};
const callbackInternalError: BusinessError = {code: ERROR_INTERNAL_ERROR, data: undefined};
const successCallbackError: BusinessError = {code: ERROR_OK, data: undefined};

const errorParamInvalid: BusinessError<string> = {code: ERROR_PARAM_INVALID, message: "Invalid parameter"};

function isInvalidParameter(bundle: BundleOption): BusinessError
{
    let error: BusinessError = {
        code: ERROR_OK,
        message: ""
    }

    let errorCode: BusinessError = {
        code: ERROR_PARAM_INVALID,
        message: "Invalid parameter"
    }
    
    if (bundle == null) {
        return errorCode;
    }
    if (bundle.bundle == null || bundle.bundle?.length === 0) {
        return errorCode;
    }
    return error;
}

function isInvalidParameter(info?: NotificationSubscribeInfo): boolean
{
    if (info == null) {
        return false;
    }
    if (info?.deviceType != undefined && info.deviceType?.length === 0) {
        return false;
    }
    return true;
}

export default namespace notificationSubscribe {
    loadLibrary("notification_subscribe_ani.z")
    export interface NotificationKey {
        id: int;
        label?: string;
    }

    class NotificationKeyInner implements NotificationKey {
        id: int = -1;
        label?: string;
    }

    export enum RemoveReason {
        CLICK_REASON_REMOVE = 1,
        CANCEL_REASON_REMOVE = 2
    }

    export native function nativeRemove(
        bundle: BundleOption,
        notificationKey: NotificationKey,
        reason: RemoveReason): void;
    export native function nativeRemove(hashCode: string, reason: RemoveReason): void;
    export native function nativeRemove(hashCodes: Array<String>, reason: RemoveReason): void;
    export native function nativeDistributeOperation(hashcode: string, operationInfo?: OperationInfo): Promise<int>;
    export native function nativeSleep(seconds: int): void;
    export native function nativeSubscribe(subscriber: NotificationSubscriber, info?: NotificationSubscribeInfo): void;
    export native function nativeUnSubscribe(subscriber: NotificationSubscriber): void
    export native function nativeSubscribeSelf(subscriber: NotificationSubscriber): void
    export native function nativeRemoveAllForBundle(bundle?: BundleOption): void;
    export native function nativeRemoveAllForUserId(userId: int): void;
    export native function nativeRemoveAll(): void;

    export function subscribe(subscriber: NotificationSubscriber, callback: AsyncCallback<void>): void {
        if (subscriber == undefined || callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { notificationSubscribe.nativeSubscribe(subscriber) });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Error): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }
    export function subscribe(
        subscriber: NotificationSubscriber,
        info: NotificationSubscribeInfo,
        callback: AsyncCallback<void>
    ): void {
        if (subscriber == undefined || info == undefined || callback == undefined) {
            throw errorParamInvalid;
        }
        if (!isInvalidParameter(info)) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { notificationSubscribe.nativeSubscribe(subscriber, info) });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Error): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }
    export function subscribe(subscriber: NotificationSubscriber, info?: NotificationSubscribeInfo): Promise<void> {
        if (subscriber == undefined) {
            throw errorParamInvalid;
        }
        if (!isInvalidParameter(info)) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => { notificationSubscribe.nativeSubscribe(subscriber, info)});
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function unsubscribe(subscriber: NotificationSubscriber, callback: AsyncCallback<void>): void {
        if (subscriber == undefined || callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => { notificationSubscribe.nativeUnSubscribe(subscriber) });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Error): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }

    export function unsubscribe(subscriber: NotificationSubscriber): Promise<void> {
        if (subscriber == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => { notificationSubscribe.nativeUnSubscribe(subscriber) });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function remove(
        bundle: BundleOption,
        notificationKey: NotificationKey,
        reason: RemoveReason,
        callback: AsyncCallback<void>
    ): void {
        if (bundle == undefined || notificationKey == undefined || reason == undefined || callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => {
            notificationSubscribe.nativeRemove(bundle, notificationKey, reason);
        });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Error): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }

    export function remove(
        bundle: BundleOption,
        notificationKey: NotificationKey,
        reason: RemoveReason
    ): Promise<void> {
        if (bundle == undefined || notificationKey == undefined || reason == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => {
                notificationSubscribe.nativeRemove(bundle, notificationKey, reason);
            });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function remove(hashCode: string, reason: RemoveReason, callback: AsyncCallback<void>): void {
        if (hashCode == undefined || reason == undefined || callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => {
            return notificationSubscribe.nativeRemove(hashCode, reason);
        });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Error): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }

    export function remove(hashCode: string, reason: RemoveReason): Promise<void> {
        if (hashCode == undefined || reason == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => {
                return notificationSubscribe.nativeRemove(hashCode, reason);
            });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function remove(hashCodes: Array<String>, reason: RemoveReason, callback: AsyncCallback<void>): void {
        if (hashCodes == undefined || reason == undefined || callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => {
            notificationSubscribe.nativeRemove(hashCodes, reason);
        });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Error): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }

    export function remove(hashCodes: Array<String>, reason: RemoveReason): Promise<void> {
        if (hashCodes == undefined || reason == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => {
                notificationSubscribe.nativeRemove(hashCodes, reason);
            });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function distributeOperation(hashcode: string, operationInfo?: OperationInfo): Promise<void> {
        if (hashcode == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): Promise<int> => {
                if (operationInfo == undefined) {
                    return notificationSubscribe.nativeDistributeOperation(hashcode);
                } else {
                    return notificationSubscribe.nativeDistributeOperation(hashcode, operationInfo);
                }
            });
            p.then(
                (e: NullishType): void => {
                    if (e == undefined) {
                        reject(rejectInternalError);
                    }
                    let result: int = e as int;
                    if (result != 0) {
                        reject(rejectInternalError);
                    } else {
                        resolve(undefined);
                    }
                }, (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export interface OperationInfo {
        actionName?: string;
        userInput?: string;
    }

    class OperationInfoInner implements OperationInfo {
        public actionName?: string;
        public userInput?: string;
    }

    export function subscribeSelf(subscriber: NotificationSubscriber): Promise<void> {
        if (subscriber == undefined) {
            throw errorParamInvalid;
        }
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => { notificationSubscribe.nativeSubscribeSelf(subscriber)});
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Error): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function removeAll(bundle: BundleOption, callback: AsyncCallback<void>): void {
        let error: BusinessError = isInvalidParameter(bundle);
        if (error.code !== ERROR_OK) {
            throw error;
        }
        if (callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => {
            return notificationSubscribe.nativeRemoveAllForBundle(bundle);
        });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Object): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }

	export function removeAll(bundle?: BundleOption): Promise<void>
    {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            let p = taskpool.execute((): void => {
                if (bundle == undefined) {
                    return notificationSubscribe.nativeRemoveAll();
                } else {
                    return notificationSubscribe.nativeRemoveAllForBundle(bundle);
                }
            });
            p.then((data: NullishType): void => {
                resolve(undefined);
            }, (error: Error): void => {
                reject(error);
            });
        });
        return pPromise;
    }

    export function removeAll(callback: AsyncCallback<void>): void {
        if (callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => {
            return notificationSubscribe.nativeRemoveAll();
        });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Object): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }

    export function removeAll(userId: int, callback: AsyncCallback<void>): void {
        if (callback == undefined) {
            throw errorParamInvalid;
        }
        let p = taskpool.execute((): void => {
            return notificationSubscribe.nativeRemoveAllForUserId(userId);
        });
        p.then(
            (e: NullishType): void => {
                callback(null, undefined);
            }, (error: Object): void => {
                let err: BusinessError = error as BusinessError;
                callback(err, undefined);
            }
        )
    }    

    export function removeAll(userId: int): Promise<void> {
    let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return notificationSubscribe.nativeRemoveAllForUserId(userId); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Error): void => {
            reject(error);
        });
    });
        return pPromise;
    }
}
