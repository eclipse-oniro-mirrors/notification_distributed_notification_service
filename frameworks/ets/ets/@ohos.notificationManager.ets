/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { BundleOption } from 'notification.NotificationCommonDef';
import { BusinessError, AsyncCallback } from '@ohos.base';
import { NotificationSlot } from 'notification.notificationSlot';

type ResolveCallback<T> = (data: T) => void;
type RejectCallback = (err: Object) => void;

export default namespace notificationManager {
    loadLibrary("notification_manager_ani_kit.z")
    export enum SlotType {
        UNKNOWN_TYPE = 0,
        SOCIAL_COMMUNICATION = 1,
        SERVICE_INFORMATION = 2,
        CONTENT_INFORMATION = 3,
        LIVE_VIEW = 4,
        CUSTOMER_SERVICE = 5,
        EMERGENCY_INFORMATION = 10,
        OTHER_TYPES = 0xFFFF,
    }

    export enum ContentType {
        NOTIFICATION_CONTENT_BASIC_TEXT,
        NOTIFICATION_CONTENT_LONG_TEXT,
        NOTIFICATION_CONTENT_PICTURE,
        NOTIFICATION_CONTENT_CONVERSATION,
        NOTIFICATION_CONTENT_MULTILINE,
        NOTIFICATION_CONTENT_SYSTEM_LIVE_VIEW,
        NOTIFICATION_CONTENT_LIVE_VIEW,
    }

    export enum SlotLevel {
        LEVEL_NONE = 0,
        LEVEL_MIN = 1,
        LEVEL_LOW = 2,
        LEVEL_DEFAULT = 3,
        LEVEL_HIGH = 4,
    }

    export enum DoNotDisturbType {
        TYPE_NONE = 0,
        TYPE_ONCE = 1,
        TYPE_DAILY = 2,
        TYPE_CLEARLY = 3,
    }

    export interface DoNotDisturbProfile {
        id: number;
        name: string;
        trustlist?: Array<BundleOption>;
    }

    class DoNotDisturbProfileInner implements DoNotDisturbProfile {
        id: number = -1;
        name: string = "";
        trustlist?: Array<BundleOption> = new Array<BundleOption>();
    }

    export interface ButtonOptions {
        buttonName: string;
    }

    class ButtonOptionsInner implements ButtonOptions {
        buttonName: string = "";
    }

    export native function nativeDisplayBadge(bundle: BundleOption, enable: boolean): void;
    export native function nativeIsBadgeDisplayed(bundle: BundleOption): boolean;
    export native function nativeGetActiveNotificationCount(): number;
    export native function nativeIsNotificationEnabled(userId?: number, bundleOption?: BundleOption): boolean;
    export native function nativegetSlotFlagsByBundle(bundle: BundleOption): int;
    export native function nativesetSlotFlagsByBundle(bundle: BundleOption, slotFlags: number): void;
    export native function nativeSetNotificationEnable(bundle: BundleOption, enable: boolean): void;
    export native function nativeisNotificationSlotEnabled(bundle: BundleOption, type: SlotType): boolean;
    export native function nativeCancelWithId(id: number): void;
    export native function nativeCancelWithIdLabel(id: number, label: string): void;
    export native function nativeCancelWithBundle(bundle: BundleOption, id: number): void;
    export native function nativeCancelAll(): void;
    export native function nativeGetSlotsByBundle(bundle: BundleOption): Array<NotificationSlot>;
    export native function nativeaddDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): void;
    export native function nativeremoveDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): void;
    export native function nativeSetNotificationEnableSlot(bundle: BundleOption, type: SlotType, enable: boolean, isForceControl?: boolean): void;
    export native function nativeSetNotificationEnableSlotByOld(bundle: BundleOption, type: SlotType, enable: boolean): void;

    export function displayBadge(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => { return nativeDisplayBadge(bundle, enable); });
        p.then((e: NullishType): void => {
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
            let err: BusinessError = error as BusinessError;
            callback(err, undefined);
        })
    }
    
    export function displayBadge(bundle: BundleOption, enable: boolean): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeDisplayBadge(bundle, enable); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function isBadgeDisplayed(bundle: BundleOption, callback: AsyncCallback<boolean>): void {
        let p = taskpool.execute((): boolean => { return nativeIsBadgeDisplayed(bundle); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }
    
    export function isBadgeDisplayed(bundle: BundleOption): Promise<boolean> {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
        let p = taskpool.execute((): boolean => { return nativeIsBadgeDisplayed(bundle); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            resolve(ret);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function getActiveNotificationCount(): Promise<number> {
        let pPromise = new Promise<number>((resolve: ResolveCallback<number>, reject: RejectCallback):void => {
            let p = taskpool.execute((): number => { return nativeGetActiveNotificationCount(); });
            p.then((data :NullishType): void => {
                let ret : number = data as number;
                resolve(ret);
            }, (err:Object): void => {
                reject(err);
            });
        });
        return pPromise;
    }

    export function isNotificationEnabled(userId: number, callback: AsyncCallback<boolean>): void
    {
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(userId, undefined); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    export function isNotificationEnabled(userId: number): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(userId, undefined); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            resolve(ret);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function isNotificationEnabled(bundleOption: BundleOption, callback: AsyncCallback<boolean>): void
    {
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(undefined, bundleOption); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    export function isNotificationEnabled(bundleOption: BundleOption): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(undefined, bundleOption); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            resolve(ret);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function isNotificationEnabled(callback: AsyncCallback<boolean>): void
    {
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(undefined, undefined); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
            let ret : boolean = false;
            let err: BusinessError = error as BusinessError;
            callback(err, ret);
        })
    }

    export function isNotificationEnabled(): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
        let p = taskpool.execute((): boolean => { return nativeIsNotificationEnabled(undefined, undefined); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            resolve(ret);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function getSlotFlagsByBundle(bundle: BundleOption): Promise<number> {
        let pPromise = new Promise<number>((resolve: ResolveCallback<number>, reject: RejectCallback): void => {
        let p = taskpool.execute((): number => { return nativegetSlotFlagsByBundle(bundle); });
        p.then((data: NullishType): void => {
            let ret : Double = data as Double;
            resolve(ret);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function setSlotFlagsByBundle(bundle: BundleOption, slotFlags: number): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativesetSlotFlagsByBundle(bundle, slotFlags); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function setNotificationEnable(bundle: BundleOption, enable: boolean): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeSetNotificationEnable(bundle, enable); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }
    
    export function setNotificationEnable(bundle: BundleOption, enable: boolean, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => { return nativeSetNotificationEnable(bundle, enable); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 1, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
        })
    }

    export function isNotificationSlotEnabled(bundle: BundleOption, type: SlotType): Promise<boolean>
    {
        let pPromise = new Promise<boolean>((resolve: ResolveCallback<boolean>, reject: RejectCallback): void => {
        let p = taskpool.execute((): boolean => { return nativeisNotificationSlotEnabled(bundle, type); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            resolve(ret);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function isNotificationSlotEnabled(bundle: BundleOption, type: SlotType, callback: AsyncCallback<boolean>): void
    {
        let p = taskpool.execute((): boolean => { return nativeisNotificationSlotEnabled(bundle, type); });
        p.then((data: NullishType): void => {
            let ret : boolean = data as boolean;
            let err: BusinessError = {code: 1, data: undefined};
            callback(err, ret);
        }, (error: Object): void => {
        })
    }

    export function cancel(id: number, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => { return nativeCancelWithId(id); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 1, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
        })
    }

    export function cancel(id: number): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeCancelWithId(id); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function cancel(id: number, label: string): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeCancelWithIdLabel(id, label); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function cancel(id: number, label: string, callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => { return nativeCancelWithIdLabel(id, label); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 1, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
        })
    }

    export function cancel(bundle: BundleOption, id: number): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeCancelWithBundle(bundle, id); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function cancelAll(): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeCancelAll(); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function cancelAll(callback: AsyncCallback<void>): void {
        let p = taskpool.execute((): void => { return nativeCancelAll(); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 1, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
        })
    }

    export function getSlotsByBundle(bundle: BundleOption, callback: AsyncCallback<Array<NotificationSlot>>): void {
        let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlotsByBundle(bundle); });
        p.then((data: NullishType): void => {
            let slots : Array<NotificationSlot> = data as Array<NotificationSlot>;
            let err: BusinessError = {code: 0, data: undefined};
            callback(err, slots);
        }, (error: Object): void => {
            let slots : Array<NotificationSlot> = [];
            let err: BusinessError = error as BusinessError;
            callback(err, slots);
        })             
    }
    
    export function getSlotsByBundle(bundle: BundleOption): Promise<Array<NotificationSlot>> {
        let pPromise = new Promise<Array<NotificationSlot>>((resolve: ResolveCallback<Array<NotificationSlot>>, reject: RejectCallback): void => {
        let p = taskpool.execute((): Array<NotificationSlot> => { return nativeGetSlotsByBundle(bundle); });
        p.then((data: NullishType): void => {
            let slots : Array<NotificationSlot> = data as Array<NotificationSlot>;
            resolve(slots);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function addDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeaddDoNotDisturbProfile(templates); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function removeDoNotDisturbProfile(templates: Array<DoNotDisturbProfile>): Promise<void> {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeremoveDoNotDisturbProfile(templates); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }

    export function setNotificationEnableSlot(bundle: BundleOption, type: SlotType, enable: boolean, callback: AsyncCallback<void>): void
    {
        let p = taskpool.execute((): void => { return nativeSetNotificationEnableSlotByOld(bundle, type, enable); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 1, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
        })
    }

    export function setNotificationEnableSlot(bundle: BundleOption, type: SlotType, enable: boolean, isForceControl: boolean, callback: AsyncCallback<void>): void
    {
        let p = taskpool.execute((): void => { return nativeSetNotificationEnableSlot(bundle, type, enable, isForceControl); });
        p.then((data: NullishType): void => {
            let err: BusinessError = {code: 1, data: undefined};
            callback(err, undefined);
        }, (error: Object): void => {
        })
    }

    export function setNotificationEnableSlot(bundle: BundleOption, type: SlotType, enable: boolean, isForceControl?: boolean): Promise<void>
    {
        let pPromise = new Promise<void>((resolve: ResolveCallback<void>, reject: RejectCallback): void => {
        let p = taskpool.execute((): void => { return nativeSetNotificationEnableSlot(bundle, type, enable, isForceControl); });
        p.then((data: NullishType): void => {
            resolve(undefined);
        }, (error: Object): void => {
            reject(error);
        });
        });
        return pPromise;
    }
}
