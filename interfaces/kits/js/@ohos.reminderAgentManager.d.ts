/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

import { AsyncCallback } from './basic';
import notification from './@ohos.notification';
import { NotificationSlot } from './notification/notificationSlot';

/**
 * Providers static methods for managing reminders, including publishing or canceling a reminder.
 * adding or removing a notification slot, and obtaining or cancelling all reminders of the current application.
 *
 * @since 9
 * @syscap SystemCapability.Notification.ReminderAgent
 * @import reminderAgentManager from '@ohos.reminderAgentManager';
 */
declare namespace reminderAgentManager {
  /**
   * Publishes a scheduled reminder.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @permission ohos.permission.PUBLISH_AGENT_REMINDER
   * @param { ReminderRequest } reminderReq - Indicates the reminder instance to publish.
   * @param { AsyncCallback<number> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   */
  function publishReminder(reminderReq: ReminderRequest, callback: AsyncCallback<number>): void;

  /**
   * Publishes a scheduled reminder.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @permission ohos.permission.PUBLISH_AGENT_REMINDER
   * @param { ReminderRequest } reminderReq - Indicates the reminder instance to publish.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   * @returns { Promise<number> } The reminder id.
   */
  function publishReminder(reminderReq: ReminderRequest): Promise<number>;

  /**
   * Cancels a reminder.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { number } reminderId - Indicates the reminder id.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   */
  function cancelReminder(reminderId: number, callback: AsyncCallback<void>): void;

  /**
   * Cancels a reminder.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { number } reminderId - Indicates the reminder id.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   * @returns { Promise<void> } The promise returned by the function.
   */
  function cancelReminder(reminderId: number): Promise<void>;

  /**
   * Obtains all the valid reminders of current application.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { AsyncCallback<Array<ReminderRequest>> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   */
  function getValidReminders(callback: AsyncCallback<Array<ReminderRequest>>): void;

  /**
   * Obtains all the valid reminders of current application.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   * @returns { Promise<Array<ReminderRequest>> } The promise returned by the function.
   */
  function getValidReminders(): Promise<Array<ReminderRequest>>;

  /**
   * Cancels all the reminders of current application.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   */
  function cancelAllReminders(callback: AsyncCallback<void>): void;

  /**
   * Cancels all the reminders of current application.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   * @returns { Promise<void> } The promise returned by the function.
   */
  function cancelAllReminders(): Promise<void>;

  /**
   * Add notification slot.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { NotificationSlot } slot - Indicates the slot.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   */
  function addNotificationSlot(slot: NotificationSlot, callback: AsyncCallback<void>): void;

  /**
   * Add notification slot.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { NotificationSlot } slot - Indicates the slot.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   * @returns { Promise<void> } The promise returned by the function.
   */
  function addNotificationSlot(slot: NotificationSlot): Promise<void>;

  /**
   * Deletes a created notification slot based on the slot type.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { notification.SlotType } slotType Indicates the type of the slot.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   */
  function removeNotificationSlot(slotType: notification.SlotType, callback: AsyncCallback<void>): void;

  /**
   * Deletes a created notification slot based on the slot type.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param { notification.SlotType } slotType Indicates the type of the slot.
   * @throws { BusinessError } 401 - If the input parameter is not valid parameter.
   * @returns { Promise<void> } The promise returned by the function.
   */
  function removeNotificationSlot(slotType: notification.SlotType): Promise<void>;

  /**
   * Declares action button type.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  export enum ActionButtonType {
    /**
     * Button for closing the reminder.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    ACTION_BUTTON_TYPE_CLOSE = 0,

    /**
     * Button for snoozing the reminder.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    ACTION_BUTTON_TYPE_SNOOZE = 1,

    /**
     * The custom button.
     * @since 10
     * @syscap SystemCapability.Notification.ReminderAgent
     * @systemapi Hide this for inner system use.
     */
     ACTION_BUTTON_TYPE_CUSTOM = 2
  }

  /**
   * Declares reminder type.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  export enum ReminderType {
    /**
     * Countdown reminder.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    REMINDER_TYPE_TIMER = 0,

    /**
     * Calendar reminder.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    REMINDER_TYPE_CALENDAR = 1,

    /**
     * Alarm reminder.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    REMINDER_TYPE_ALARM = 2
  }

  /**
   * Action button information. The button will show on displayed reminder.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  interface ActionButton {
    /**
     * Text on the button.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    title: string;

    /**
     * Button type.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    type: ActionButtonType;

    /**
     * Information about the ability that is redirected to when the button is clicked.
     * @since 10
     * @syscap SystemCapability.Notification.ReminderAgent
     * @systemapi Hide this for inner system use.
     */
     wantAgent?: WantAgent;
  }

  /**
   * Want agent information.
   * It will switch to target ability when you click the displayed reminder.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  interface WantAgent {
    /**
     * Name of the package redirected to when the reminder notification is clicked.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    pkgName: string;

    /**
     * Name of the ability that is redirected to when the reminder notification is clicked.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    abilityName: string;
  }

  /**
   * Max screen want agent information.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  interface MaxScreenWantAgent {
    /**
     * Name of the package that is automatically started when the reminder arrives and the device is not in use.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    pkgName: string;

    /**
     * Name of the ability that is automatically started when the reminder arrives and the device is not in use.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    abilityName: string;
  }

  /**
   * Reminder Common information.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  interface ReminderRequest {
    /**
     * Type of the reminder.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    reminderType: ReminderType;

     /**
     * Action button displayed on the reminder notification.
     * (The parameter is optional. Up to two buttons are supported).
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    /**
     * Action button displayed on the reminder notification.
     * (The parameter is optional. Up to three buttons are supported).
     * @since 10
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    actionButton?: [ActionButton?, ActionButton?, ActionButton?];

    /**
     * Information about the ability that is redirected to when the notification is clicked.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    wantAgent?: WantAgent;

    /**
     * Information about the ability that is automatically started when the reminder arrives.
     * If the device is in use, a notification will be displayed.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    maxScreenWantAgent?: MaxScreenWantAgent;

    /**
     * Ringing duration.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    ringDuration?: number;

    /**
     * Number of reminder snooze times.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    snoozeTimes?: number;

    /**
     * Reminder snooze interval.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    timeInterval?: number;

    /**
     * Reminder title.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    title?: string;

    /**
     * Reminder content.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    content?: string;

    /**
     * Content to be displayed when the reminder is expired.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    expiredContent?: string;

    /**
     * Content to be displayed when the reminder is snoozing.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    snoozeContent?: string;

    /**
     * notification id. If there are reminders with the same ID, the later one will overwrite the earlier one.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    notificationId?: number;

    /**
     * Type of the slot used by the reminder.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    slotType?: notification.SlotType;

    /**
     * Whether the notification is automatically cleared.
     * @since 10
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    tapDismissed?: boolean;

    /**
     * Time when the notification is automatically cleared.
     * @since 10
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    autoDeletedTime?: number;
  }

  interface ReminderRequestCalendar extends ReminderRequest {
    /**
     * Reminder time.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    dateTime: LocalDateTime;

    /**
     * Month in which the reminder repeats.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    repeatMonths?: Array<number>;

    /**
     * Date on which the reminder repeats.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    repeatDays?: Array<number>;
  }

  /**
   * Alarm reminder information.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  interface ReminderRequestAlarm extends ReminderRequest {
    /**
     * Hour portion of the reminder time.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    hour: number;

    /**
     * minute portion of the reminder time.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    minute: number;

    /**
     * Days of a week when the reminder repeates.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    daysOfWeek?: Array<number>;
  }

  /**
   * CountDown reminder information.
   *
   * @since 9
   * @syscap SystemCapability.Notification.ReminderAgent
   */
  interface ReminderRequestTimer extends ReminderRequest {
    triggerTimeInSeconds: number;
  }

  interface LocalDateTime {
    /**
     * value of year.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    year: number;

    /**
     * value of month.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    month: number;

    /**
     * value of day.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    day: number;

    /**
     * value of hour.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    hour: number;

    /**
     * value of minute.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    minute: number;

    /**
     * value of second.
     * @since 9
     * @syscap SystemCapability.Notification.ReminderAgent
     */
    second?: number;
  }
}
export default reminderAgentManager;
