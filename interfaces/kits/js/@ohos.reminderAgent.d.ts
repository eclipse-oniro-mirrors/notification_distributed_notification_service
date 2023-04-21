/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

import { AsyncCallback } from './@ohos.base';
import notification from './@ohos.notification';
import { NotificationSlot } from './notification/notificationSlot';

/**
 * Providers static methods for managing reminders, including publishing or canceling a reminder.
 * adding or removing a notification slot, and obtaining or cancelling all reminders of the current application.
 *
 * @since 7
 * @syscap SystemCapability.Notification.ReminderAgent
 * @import reminderAgent from '@ohos.reminderAgent';
 * @deprecated since 9
 * @useinstead reminderAgentManager
 */
declare namespace reminderAgent {
  /**
   * Publishes a scheduled reminder.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @permission ohos.permission.PUBLISH_AGENT_REMINDER
   * @param reminderReq Indicates the reminder instance to publish.
   * @param callback Indicates the callback function.
   * @returns reminder id.
   * @deprecated since 9
   * @useinstead reminderAgentManager.publishReminder
   */
  function publishReminder(reminderReq: ReminderRequest, callback: AsyncCallback<number>): void;
  function publishReminder(reminderReq: ReminderRequest): Promise<number>;

  /**
   * Cancels a reminder.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param reminderId Indicates the reminder id.
   * @param callback Indicates the callback function.
   * @deprecated since 9
   * @useinstead reminderAgentManager.cancelReminder
   */
  function cancelReminder(reminderId: number, callback: AsyncCallback<void>): void;
  function cancelReminder(reminderId: number): Promise<void>;

  /**
   * Obtains all the valid reminders of current application.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param callback Indicates the callback function.
   * @deprecated since 9
   * @useinstead reminderAgentManager.getValidReminders
   */
  function getValidReminders(callback: AsyncCallback<Array<ReminderRequest>>): void;
  function getValidReminders(): Promise<Array<ReminderRequest>>;

  /**
   * Cancels all the reminders of current application.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param callback Indicates the callback function.
   * @deprecated since 9
   * @useinstead reminderAgentManager.cancelAllReminders
   */
  function cancelAllReminders(callback: AsyncCallback<void>): void;
  function cancelAllReminders(): Promise<void>;

  /**
   * Add notification slot.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param slot Indicates the slot.
   * @param callback Indicates the callback function.
   * @deprecated since 9
   * @useinstead reminderAgentManager.addNotificationSlot
   */
  function addNotificationSlot(slot: NotificationSlot, callback: AsyncCallback<void>): void;
  function addNotificationSlot(slot: NotificationSlot): Promise<void>;

  /**
   * Deletes a created notification slot based on the slot type.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @param slotType Indicates the type of the slot.
   * @param callback Indicates the callback function.
   * @deprecated since 9
   * @useinstead reminderAgentManager.removeNotificationSlot
   */
  function removeNotificationSlot(slotType: notification.SlotType, callback: AsyncCallback<void>): void;
  function removeNotificationSlot(slotType: notification.SlotType): Promise<void>;

  /**
   * Declares action button type.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.ActionButtonType
   */
  export enum ActionButtonType {
    /**
     * Button for closing the reminder.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ActionButtonType.ACTION_BUTTON_TYPE_CLOSE
     */
    ACTION_BUTTON_TYPE_CLOSE = 0,

    /**
     * Button for snoozing the reminder.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ActionButtonType.ACTION_BUTTON_TYPE_SNOOZE
     */
    ACTION_BUTTON_TYPE_SNOOZE = 1
  }

  /**
   * Declares reminder type.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.ReminderType
   */
  export enum ReminderType {
    /**
     * Countdown reminder.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderType.REMINDER_TYPE_TIMER
     */
    REMINDER_TYPE_TIMER = 0,

    /**
     * Calendar reminder.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderType.REMINDER_TYPE_CALENDAR
     */
    REMINDER_TYPE_CALENDAR = 1,

    /**
     * Alarm reminder.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderType.REMINDER_TYPE_ALARM
     */
    REMINDER_TYPE_ALARM = 2
  }

  /**
   * Action button information. The button will show on displayed reminder.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.ActionButton
   */
  interface ActionButton {
    /**
     * Text on the button.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ActionButton.title
     */
    title: string;

    /**
     * Button type.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ActionButton.type
     */
    type: ActionButtonType;
  }

  /**
   * Want agent information.
   * It will switch to target ability when you click the displayed reminder.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.WantAgent
   */
  interface WantAgent {
    /**
     * Name of the package redirected to when the reminder notification is clicked.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.WantAgent.pkgName
     */
    pkgName: string;

    /**
     * Name of the ability that is redirected to when the reminder notification is clicked.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.WantAgent.abilityName
     */
    abilityName: string;
  }

  /**
   * Max screen want agent information.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.MaxScreenWantAgent
   */
  interface MaxScreenWantAgent {
    /**
     * Name of the package that is automatically started when the reminder arrives and the device is not in use.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.MaxScreenWantAgent.pkgName
     */
    pkgName: string;

    /**
     * Name of the ability that is automatically started when the reminder arrives and the device is not in use.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.MaxScreenWantAgent.abilityName
     */
    abilityName: string;
  }

  /**
   * Reminder Common information.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.ReminderRequest
   */
  interface ReminderRequest {
    /**
     * Type of the reminder.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.reminderType
     */
    reminderType: ReminderType;

    /**
     * Action button displayed on the reminder notification.
     * (The parameter is optional. Up to two buttons are supported).
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.actionButton
     */
    actionButton?: [ActionButton?, ActionButton?];

    /**
     * Information about the ability that is redirected to when the notification is clicked.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.wantAgent
     */
    wantAgent?: WantAgent;

    /**
     * Information about the ability that is automatically started when the reminder arrives.
     * If the device is in use, a notification will be displayed.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.maxScreenWantAgent
     */
    maxScreenWantAgent?: MaxScreenWantAgent;

    /**
     * Ringing duration.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.ringDuration
     */
    ringDuration?: number;

    /**
     * Number of reminder snooze times.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.snoozeTimes
     */
    snoozeTimes?: number;

    /**
     * Reminder snooze interval.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.timeInterval
     */
    timeInterval?: number;

    /**
     * Reminder title.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.title
     */
    title?: string;

    /**
     * Reminder content.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.content
     */
    content?: string;

    /**
     * Content to be displayed when the reminder is expired.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.expiredContent
     */
    expiredContent?: string;

    /**
     * Content to be displayed when the reminder is snoozing.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.snoozeContent
     */
    snoozeContent?: string;

    /**
     * notification id. If there are reminders with the same ID, the later one will overwrite the earlier one.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.notificationId
     */
    notificationId?: number;

    /**
     * Type of the slot used by the reminder.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequest.slotType
     */
    slotType?: notification.SlotType;
  }

  /**
   * @deprecated since 9
   * @useinstead reminderAgentManager.ReminderRequestCalendar
   */
  interface ReminderRequestCalendar extends ReminderRequest {
    /**
     * Reminder time.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestCalendar.dateTime
     */
    dateTime: LocalDateTime;

    /**
     * Month in which the reminder repeats.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestCalendar.repeatMonths
     */
    repeatMonths?: Array<number>;

    /**
     * Date on which the reminder repeats.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestCalendar.repeatDays
     */
    repeatDays?: Array<number>;
  }

  /**
   * Alarm reminder information.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.ReminderRequestAlarm
   */
  interface ReminderRequestAlarm extends ReminderRequest {
    /**
     * Hour portion of the reminder time.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestAlarm.hour
     */
    hour: number;

    /**
     * minute portion of the remidner time.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestAlarm.minute
     */
    minute: number;

    /**
     * Days of a week when the reminder repeates.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestAlarm.daysOfWeek
     */
    daysOfWeek?: Array<number>;
  }

  /**
   * CountDown reminder information.
   *
   * @since 7
   * @syscap SystemCapability.Notification.ReminderAgent
   * @deprecated since 9
   * @useinstead reminderAgentManager.ReminderRequestTimer
   */
  interface ReminderRequestTimer extends ReminderRequest {
    triggerTimeInSeconds: number;
  }

  interface LocalDateTime {
    /**
     * value of year.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestTimer.year
     */
    year: number;

    /**
     * value of month.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestTimer.month
     */
    month: number;

    /**
     * value of day.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestTimer.day
     */
    day: number;

    /**
     * value of hour.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestTimer.hour
     */
    hour: number;

    /**
     * value of minute.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestTimer.minute
     */
    minute: number;

    /**
     * value of second.
     * @since 7
     * @syscap SystemCapability.Notification.ReminderAgent
     * @deprecated since 9
     * @useinstead reminderAgentManager.ReminderRequestTimer.second
     */
    second?: number;
  }
}
export default reminderAgent;
