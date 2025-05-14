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
type RejectCallback = (err: Object) => void;

export default namespace notificationSubscribe {
    export interface NotificationKey {
        id: number;
        label?: string;
    }

    class NotificationKeyInner implements NotificationKey {
        id: number = -1;
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
    export native function nativeDistributeOperation(hashcode: string, operationInfo?: OperationInfo): Promise<void>;
    export native function nativeSleep(seconds: int): void;
    export native function nativeSubscribe(subscriber: NotificationSubscriber, info?: NotificationSubscribeInfo): void;
    export native function nativeUnSubscribe(subscriber: NotificationSubscriber): void

    export function subscribe(subscriber: NotificationSubscriber, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => { notificationSubscribe.nativeSubscribe(subscriber) });
        p.then(
            (e: NullishType): void => {
                let err: BusinessError<void> = {code: 0, data: undefined};
                callback(err, undefined);
            }, (error: Object): void => {
            }
        )
    }
    export function subscribe(
        subscriber: NotificationSubscriber,
        info: NotificationSubscribeInfo,
        callback: AsyncCallback<void>
    ): void {
        let p = taskpool.execute((): void => { notificationSubscribe.nativeSubscribe(subscriber, info) });
        p.then(
            (e: NullishType): void => {
                let err: BusinessError<void> = {code: 0, data: undefined};
                callback(err, undefined);
            }, (error: Object): void => {
            }
        )
    }
    export function subscribe(subscriber: NotificationSubscriber, info?: NotificationSubscribeInfo): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => { notificationSubscribe.nativeSubscribe(subscriber, info)});
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Object): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function unsubscribe(subscriber: NotificationSubscriber, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => { notificationSubscribe.nativeUnSubscribe(subscriber) });
        p.then(
            (e: NullishType): void => {
                let err: BusinessError<void> = {code: 0, data: undefined};
                callback(err, undefined);
            }, (error: Object): void => {
            }
        )
    }

    export function unsubscribe(subscriber: NotificationSubscriber): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => { notificationSubscribe.nativeUnSubscribe(subscriber) });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Object): void => {
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
        let p = taskpool.execute((): void => {
            notificationSubscribe.nativeRemove(bundle, notificationKey, reason);
        });
        p.then(
            (e: NullishType): void => {
                let err: BusinessError<void> = {code: 0, data: undefined};
                callback(err, undefined);
            }, (error: Object): void => {
            }
        )
    }

    export function remove(
        bundle: BundleOption,
        notificationKey: NotificationKey,
        reason: RemoveReason
    ): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => {
                notificationSubscribe.nativeRemove(bundle, notificationKey, reason);
            });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Object): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function remove(hashCode: string, reason: RemoveReason, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => {
            return notificationSubscribe.nativeRemove(hashCode, reason);
        });
        p.then(
            (e: NullishType): void => {
                let err: BusinessError<void> = {code: 0, data: undefined};
                callback(err, undefined);
            }, (error: Object): void => {
            }
        )
    }

    export function remove(hashCode: string, reason: RemoveReason): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => {
                return notificationSubscribe.nativeRemove(hashCode, reason);
            });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Object): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function remove(hashCodes: Array<String>, reason: RemoveReason, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => {
            notificationSubscribe.nativeRemove(hashCodes, reason);
        });
        p.then(
            (e: NullishType): void => {
                let err: BusinessError<void> = {code: 0, data: undefined};
                callback(err, undefined);
            }, (error: Object): void => {
            }
        )
    }

    export function remove(hashCodes: Array<String>, reason: RemoveReason): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void =>{
            let p = taskpool.execute((): void => {
                notificationSubscribe.nativeRemove(hashCodes, reason);
            });
            p.then(
                (e: NullishType): void => {
                    resolve(undefined);
                }, (error: Object): void => {
                    reject(error);
                }
            )
        });
        return pPromise;
    }

    export function distributeOperation(hashcode: string, operationInfo?: OperationInfo): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
            console.log("===============================1111");
            let p = taskpool.execute((): Object => {
                if (operationInfo == undefined) {
                    return notificationSubscribe.nativeDistributeOperation(hashcode);
                } else {
                    return notificationSubscribe.nativeDistributeOperation(hashcode, operationInfo);
                }
            });
            console.log("===============================2222");
            p.then(
                (e: NullishType): void => {
                    try {
                        console.log("===============================3333");
                        let stsPromise = e as String;
                        console.log("==================================================================== data", stsPromise);
                        resolve(undefined);
                    } catch(error) {
                        console.log("===============================6666. error", JSON.stringify(error));
                    }
                }, (error: Object): void => {
                    console.log("===============================4444");
                    reject(error);
                }
            )
            console.log("===============================5555");
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
}
/*
loadLibrary("notification_subscribe_ani_kit.z");
let TAG = 'SUB_NOTIFICATION_ANS_SYSTEM_API_TEST ===>'
function StsRemoveForHashCodeAsyncCallback()
{
    console.log("StsRemoveForHashCodeAsyncCallback START");
    try {
        notificationSubscribe.remove("device_0_1", notificationSubscribe.RemoveReason.CLICK_REASON_REMOVE, (err: BusinessError<void>, data: NullishType): void => {
            if (err) {
                console.info(`${TAG} StsRemoveForHashCode AsyncCallback errCode: ${err.code}`)
            } else {
                console.info(`${TAG} StsRemoveForHashCode AsyncCallback success`)
            }
        });
    } catch(error) {
        console.info("StsRemoveForHashCodeAsyncCallback error ", JSON.stringify(error));
    }
    console.info(`${TAG} StsRemoveForHashCodeAsyncCallback END`);
}

function StsRemoveForHashCodePromise()
{
    console.log("StsRemoveForHashCodeAsyncCallback START");
    try {
        let p = notificationSubscribe.remove("device_0_1", notificationSubscribe.RemoveReason.CLICK_REASON_REMOVE);
        p.then(
            (data: NullishType): void => {
                console.info(`${TAG} StsRemoveForHashCodePromise suc..`);
            }, (error: Object): void => {
                console.info("StsRemoveForHashCodeAsyncCallback error ", JSON.stringify(error));
            }
        )
    } catch(error) {
        console.info("StsRemoveForHashCodeAsyncCallback error ", JSON.stringify(error));
    }
    console.info(`${TAG} StsRemoveForHashCodeAsyncCallback END`);
}

function StsRemoveForBundleAsyncCallback()
{
    console.log("StsRemoveForBundleAsyncCallback START");
    let option: BundleOption = { bundle: 'device_0_1', uid: 10001 };
    let key: notificationSubscribe.NotificationKey = { id: 2001, label: 'label' };
    try {
        notificationSubscribe.remove(option, key, notificationSubscribe.RemoveReason.CLICK_REASON_REMOVE, (err: BusinessError<void>, data: NullishType): void => {
            if (err) {
                console.info(`${TAG} StsRemoveForBundleAsyncCallback errCode: ${err.code}`)
            } else {
                console.info(`${TAG} StsRemoveForBundleAsyncCallback success`)
            }
        });
    } catch(error) {
        console.info("StsRemoveForBundleAsyncCallback error ", JSON.stringify(error));
    }
    console.info(`${TAG} StsRemoveForBundleAsyncCallback END`);
}

function StsRemoveForBundlePromise()
{
    console.log("StsRemoveForBundlePromise START");
    let option: BundleOption = { bundle: 'device_0_1', uid: 10001 };
    let key: notificationSubscribe.NotificationKey = { id: 2001, label: 'label' };
    try {
        let p = notificationSubscribe.remove(option, key, notificationSubscribe.RemoveReason.CLICK_REASON_REMOVE);
        p.then(
            (data: NullishType): void => {
                console.info(`${TAG} StsRemoveForBundlePromise suc..`);
            }, (error: Object): void => {
                console.info("StsRemoveForBundlePromise error ", JSON.stringify(error));
            }
        )
    } catch(error) {
        console.info("StsRemoveForBundlePromise error ", JSON.stringify(error));
    }
    console.info(`${TAG} StsRemoveForBundlePromise END`);
}

function StsRemoveForHashCodesAsyncCallback()
{
    console.log("StsRemoveForHashCodesAsyncCallback START");
    let hasCodes = ['str1', 'str2', 'str3'];
    try {
        notificationSubscribe.remove(hasCodes, notificationSubscribe.RemoveReason.CLICK_REASON_REMOVE, (err: BusinessError<void>, data: NullishType): void => {
            if (err) {
                console.info(`${TAG} StsRemoveForHashCodesAsyncCallback errCode: ${err.code}`)
            } else {
                console.info(`${TAG} StsRemoveForHashCodesAsyncCallback success`)
            }
        });
    } catch(error) {
        console.info("StsRemoveForHashCodesAsyncCallback error ", JSON.stringify(error));
    }
    console.info(`${TAG} StsRemoveForHashCodesAsyncCallback END`);
}

function StsRemoveForHashCodesPromise()
{
    console.log("StsRemoveForHashCodesPromise START");
    let hasCodes = ['str1', 'str2', 'str3'];
    try {
        let p = notificationSubscribe.remove(hasCodes, notificationSubscribe.RemoveReason.CLICK_REASON_REMOVE);
        p.then(
            (data: NullishType): void => {
                console.info(`${TAG} StsRemoveForHashCodesPromise suc..`);
            }, (error: Object): void => {
                console.info("StsRemoveForHashCodesPromise error ", JSON.stringify(error));
            }
        )
    } catch(error) {
        console.info("StsRemoveForHashCodesPromise error ", JSON.stringify(error));
    }
    console.info(`${TAG} StsRemoveForHashCodesPromise END`);
}

function StsDistributeOperationPromise()
{
    console.log("StsDistributeOperationPromise START");
    let hasCode = "hasCode";
    let info: notificationSubscribe.OperationInfo = {
        actionName: "actionName",
        userInput: "userInput"
    }
    try {
        console.info(`${TAG} StsDistributeOperationPromise THEN Before `);
        let p = notificationSubscribe.distributeOperation(hasCode, info);
        console.info(`${TAG} StsDistributeOperationPromise THEN After`);
        p.then(
            (data: NullishType): void => {
                console.info(`${TAG} StsDistributeOperationPromise suc..`);
            }, (error: Object): void => {
                console.info("StsDistributeOperationPromise error ", JSON.stringify(error));
            }
        )
    } catch(error) {
        console.info("StsDistributeOperationPromise error ", JSON.stringify(error));
    }
    console.info(`${TAG} StsDistributeOperationPromise END`);
}

function StsSubscribeAsyncCallback()
{
    try {
        let sub: NotificationSubscriber = {
            
        }
        console.info("StsSubscribeAsyncCallback Before");
        notificationSubscribe.subscribe(sub, (err: BusinessError<void>, data: NullishType): void => {
            console.log('StsSubscribeAsyncCallback suc...');
        });
        console.info("StsSubscribeAsyncCallback After");
    } catch(error) {
        console.info("StsSubscribeAsyncCallback error ", JSON.stringify(error));
    }
}

// type FnOnDisconnect = onDisconnect: () => void;

class TestNotificationSubscriber implements NotificationSubscriber {
    onDisconnect?: () => void = () => {
        console.log('====================== onDisconnect');
    }

    onConnect?: () => void = () => {
        console.log('====================== onConnect');
    }

    onDestroy?: () => void = () => {
        console.log('====================== onDestroy');
    }
}

function StsSubscribeForInfoAsynCallback()
{
    try {
        let sub: NotificationSubscriber = new TestNotificationSubscriber;

        let info: NotificationSubscribeInfo = {
            bundleNames: ['zxh', 'xhz', 'hzx'],
            userId: 1000,
            deviceType: 'deviceType test',
            filterLimit: 1001
        }
        console.info("StsSubscribeForInfoAsynCallback Before");
        notificationSubscribe.subscribe(sub, info, (err: BusinessError<void>, data: NullishType): void => {
            console.log('StsSubscribeForInfoAsynCallback suc...');
        });
        console.info("StsSubscribeForInfoAsynCallback After");
    } catch(error) {
        console.info("StsSubscribeForInfoAsynCallback error ", JSON.stringify(error));
    }
}

function StsSubscribePromise()
{
    try {
        let sub: NotificationSubscriber = {
            
        }

        let info: NotificationSubscribeInfo = {
            bundleNames: ['zxh', 'xhz', 'hzx'],
            userId: 1000,
            deviceType: 'deviceType test',
            filterLimit: 1001
        }
        console.log(JSON.stringify(info));
        console.info("StsSubscribePromise Before");
        let p = notificationSubscribe.subscribe(sub, info);
        p.then(
            (e: NullishType): void => {
                console.info("StsSubscribePromise suc..");
            }, (error: Object): void => {
                console.info("StsSubscribePromise error ", JSON.stringify(error));
            }
        )

        let p1 = notificationSubscribe.unsubscribe(sub);
        p1.then(
            (e: NullishType): void => {
                console.info("un StsSubscribePromise suc.. ");
            }, (error: Object): void => {
                console.info("un StsSubscribePromise error ", JSON.stringify(error));
            }
        )
    } catch(error) {
        console.info("StsSubscribePromise error ", JSON.stringify(error));
    }
}

function main()
{
    StsDistributeOperationPromise();
    StsSubscribeAsyncCallback();
    StsSubscribeForInfoAsynCallback();
    StsSubscribePromise();
}
*/