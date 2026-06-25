/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "ans_service_errors.h"
#include "ans_inner_errors.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

class AnsServiceErrorsTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: InnerErrorToExternal_BasicMapping_001
 * @tc.desc: 验证 InnerErrorCode 到外部错误码的基本映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_BasicMapping_001, TestSize.Level1)
{
    // 权限类
    EXPECT_EQ(ERROR_PERMISSION_DENIED, InnerErrorToExternal(ERR_ANS_INNER_PERMISSION_DENIED));
    EXPECT_EQ(ERROR_NOT_SYSTEM_APP, InnerErrorToExternal(ERR_ANS_INNER_NON_SYSTEM_APP));
    EXPECT_EQ(ERROR_NOT_SYSTEM_APP, InnerErrorToExternal(ERR_ANS_INNER_NOT_SYSTEM_SERVICE));
    EXPECT_EQ(ERROR_NOTIFICATION_CLOSED, InnerErrorToExternal(ERR_ANS_INNER_NOT_ALLOWED));

    // 参数类
    EXPECT_EQ(ERROR_PARAM_INVALID, InnerErrorToExternal(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_EQ(ERROR_PARAM_INVALID, InnerErrorToExternal(ERR_ANS_INNER_INVALID_UID));
    EXPECT_EQ(ERROR_BUNDLE_NOT_FOUND, InnerErrorToExternal(ERR_ANS_INNER_INVALID_PID));
    EXPECT_EQ(ERROR_BUNDLE_NOT_FOUND, InnerErrorToExternal(ERR_ANS_INNER_INVALID_BUNDLE));
    EXPECT_EQ(ERROR_BUNDLE_INVALID, InnerErrorToExternal(ERR_ANS_INNER_INVALID_BUNDLE_OPTION));

    // 基础设施类
    EXPECT_EQ(ERROR_SERVICE_CONNECT_ERROR, InnerErrorToExternal(ERR_ANS_INNER_SERVICE_NOT_READY));
    EXPECT_EQ(ERROR_SERVICE_CONNECT_ERROR, InnerErrorToExternal(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_EQ(ERROR_IPC_ERROR, InnerErrorToExternal(ERR_ANS_INNER_PARCELABLE_FAILED));
    EXPECT_EQ(ERROR_IPC_ERROR, InnerErrorToExternal(ERR_ANS_INNER_TRANSACT_FAILED));
    EXPECT_EQ(ERROR_IPC_ERROR, InnerErrorToExternal(ERR_ANS_INNER_REMOTE_DEAD));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_NO_MEMORY));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_TASK_ERR));
}

/**
 * @tc.name: InnerErrorToExternal_NotificationAndSlot_001
 * @tc.desc: 验证通知管理和 Slot 类的 InnerErrorCode 到外部错误码映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_NotificationAndSlot_001, TestSize.Level1)
{
    // 通知管理类
    EXPECT_EQ(ERROR_NOTIFICATION_NOT_EXIST, InnerErrorToExternal(ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS));
    EXPECT_EQ(ERROR_NOTIFICATION_UNREMOVABLE, InnerErrorToExternal(ERR_ANS_INNER_NOTIFICATION_IS_UNREMOVABLE));
    EXPECT_EQ(ERROR_OVER_MAX_NUM_PER_SECOND, InnerErrorToExternal(ERR_ANS_INNER_OVER_MAX_ACTIVE_PERSECOND));
    EXPECT_EQ(ERROR_OVER_MAX_NUM_PER_SECOND, InnerErrorToExternal(ERR_ANS_INNER_OVER_MAX_UPDATE_PERSECOND));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_DUPLICATE_MSG));
    EXPECT_EQ(ERROR_EXPIRED_NOTIFICATION, InnerErrorToExternal(ERR_ANS_INNER_EXPIRED_NOTIFICATION));
    EXPECT_EQ(ERROR_REPEAT_SET, InnerErrorToExternal(ERR_ANS_INNER_REPEAT_CREATE));
    EXPECT_EQ(ERROR_REPEAT_SET, InnerErrorToExternal(ERR_ANS_INNER_END_NOTIFICATION));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_DIALOG_POP_SUCCEEDED));

    // Slot 类
    EXPECT_EQ(ERROR_INTERNAL_ERROR,
        InnerErrorToExternal(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED));
    EXPECT_EQ(ERROR_INTERNAL_ERROR,
        InnerErrorToExternal(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST));
    EXPECT_EQ(ERROR_READ_TEMPLATE_CONFIG_FAILED,
        InnerErrorToExternal(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED));
    EXPECT_EQ(ERROR_SLOT_CLOSED,
        InnerErrorToExternal(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_ENABLED));
}

/**
 * @tc.name: InnerErrorToExternal_SpecialGroups_001
 * @tc.desc: 验证分布式、地理围栏、Push、弹窗、加密、代理/扩展类的映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_SpecialGroups_001, TestSize.Level1)
{
    // 分布式
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToExternal(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToExternal(ERR_ANS_INNER_DISTRIBUTED_GET_INFO_FAILED));
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_TIMEOUT,
        InnerErrorToExternal(ERR_ANS_INNER_OPERATION_TIMEOUT));

    // 地理围栏
    EXPECT_EQ(ERROR_GEOFENCE_ENABLED, InnerErrorToExternal(ERR_ANS_INNER_GEOFENCE_ENABLED));
    EXPECT_EQ(ERROR_PARAM_INVALID, InnerErrorToExternal(ERR_ANS_INNER_GEOFENCE_EXCEEDED));
    EXPECT_EQ(ERROR_SERVICE_CONNECT_ERROR,
        InnerErrorToExternal(ERR_ANS_INNER_GEOFENCING_OPERATION_TIMEOUT));
    EXPECT_EQ(ERROR_LOCATION_CLOSED, InnerErrorToExternal(ERR_ANS_INNER_ERROR_LOCATION_CLOSED));
    EXPECT_EQ(ERROR_AWARNESS_SUGGESTIONS_CLOSED,
        InnerErrorToExternal(ERR_ANS_INNER_AWARNESS_SUGGESTIONS_CLOSED));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_CHECK_WEAK_NETWORK));

    // Push
    EXPECT_EQ(ERROR_NO_RIGHT, InnerErrorToExternal(ERR_ANS_INNER_PUSH_CHECK_FAILED));
    EXPECT_EQ(ERROR_NO_RIGHT, InnerErrorToExternal(ERR_ANS_INNER_PUSH_CHECK_UNREGISTERED));
    EXPECT_EQ(ERROR_NETWORK_UNREACHABLE,
        InnerErrorToExternal(ERR_ANS_INNER_PUSH_CHECK_NETWORK_UNREACHABLE));

    // 弹窗
    EXPECT_EQ(ERROR_DIALOG_IS_POPPING, InnerErrorToExternal(ERR_ANS_INNER_DIALOG_IS_POPPING));

    // 加密
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_ENCRYPT_FAIL));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_DECRYPT_FAIL));

    // 代理/扩展
    EXPECT_EQ(ERROR_NO_AGENT_SETTING, InnerErrorToExternal(ERR_ANS_INNER_NO_AGENT_SETTING));
    EXPECT_EQ(ERROR_NO_PROFILE_TEMPLATE, InnerErrorToExternal(ERR_ANS_INNER_NO_PROFILE_TEMPLATE));
    EXPECT_EQ(ERROR_REJECTED_WITH_DISABLE_NOTIFICATION,
        InnerErrorToExternal(ERR_ANS_INNER_REJECTED_WITH_DISABLE_NOTIFICATION));
    EXPECT_EQ(ERROR_NO_CUSTOM_RINGTONE_INFO,
        InnerErrorToExternal(ERR_ANS_INNER_NO_CUSTOM_RINGTONE_INFO));
    EXPECT_EQ(ERROR_INTERNAL_ERROR,
        InnerErrorToExternal(ERR_ANS_INNER_VOICE_SUMMARY_COUNT_EXCEEDED));
    EXPECT_EQ(ERROR_SYSTEM_CAP_ERROR, InnerErrorToExternal(ERR_ANS_INNER_DEVICE_NOT_SUPPORT));
    EXPECT_EQ(ERROR_NOT_IMPL_EXTENSIONABILITY,
        InnerErrorToExternal(ERR_ANS_INNER_NOT_IMPL_EXTENSIONABILITY));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_DLP_HAP));
    EXPECT_EQ(ERR_NOTIFICATION_NOT_SUPPORT,
        InnerErrorToExternal(ERR_ANS_INNER_NOTIFICATION_SNOOZE_NOTALLOWED));
}

/**
 * @tc.name: InnerErrorToExternal_UnknownCode_001
 * @tc.desc: 验证未知 InnerErrorCode 直接透传原值
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_UnknownCode_001, TestSize.Level1)
{
    int32_t unknownCode = 999999;
    EXPECT_EQ(unknownCode, InnerErrorToExternal(unknownCode));
}

/**
 * @tc.name: InnerErrorToNative_BasicMapping_001
 * @tc.desc: 验证 InnerErrorCode 到 Inner API 错误码的基本映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_BasicMapping_001, TestSize.Level1)
{
    // 权限类
    EXPECT_EQ(ERR_ANS_PERMISSION_DENIED, InnerErrorToNative(ERR_ANS_INNER_PERMISSION_DENIED));
    EXPECT_EQ(ERR_ANS_NON_SYSTEM_APP, InnerErrorToNative(ERR_ANS_INNER_NON_SYSTEM_APP));
    EXPECT_EQ(ERR_ANS_NOT_SYSTEM_SERVICE, InnerErrorToNative(ERR_ANS_INNER_NOT_SYSTEM_SERVICE));
    EXPECT_EQ(ERR_ANS_NOT_ALLOWED, InnerErrorToNative(ERR_ANS_INNER_NOT_ALLOWED));

    // 参数类
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, InnerErrorToNative(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_EQ(ERR_ANS_INVALID_UID, InnerErrorToNative(ERR_ANS_INNER_INVALID_UID));
    EXPECT_EQ(ERR_ANS_INVALID_PID, InnerErrorToNative(ERR_ANS_INNER_INVALID_PID));
    EXPECT_EQ(ERR_ANS_INVALID_BUNDLE, InnerErrorToNative(ERR_ANS_INNER_INVALID_BUNDLE));
    EXPECT_EQ(ERR_ANS_INVALID_BUNDLE_OPTION, InnerErrorToNative(ERR_ANS_INNER_INVALID_BUNDLE_OPTION));

    // 基础设施类
    EXPECT_EQ(ERR_ANS_SERVICE_NOT_READY, InnerErrorToNative(ERR_ANS_INNER_SERVICE_NOT_READY));
    EXPECT_EQ(ERR_ANS_SERVICE_NOT_CONNECTED, InnerErrorToNative(ERR_ANS_INNER_SERVICE_NOT_CONNECTED));
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, InnerErrorToNative(ERR_ANS_INNER_PARCELABLE_FAILED));
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, InnerErrorToNative(ERR_ANS_INNER_TRANSACT_FAILED));
    EXPECT_EQ(ERR_ANS_REMOTE_DEAD, InnerErrorToNative(ERR_ANS_INNER_REMOTE_DEAD));
    EXPECT_EQ(ERR_ANS_NO_MEMORY, InnerErrorToNative(ERR_ANS_INNER_NO_MEMORY));
    EXPECT_EQ(ERR_ANS_TASK_ERR, InnerErrorToNative(ERR_ANS_INNER_TASK_ERR));
}

/**
 * @tc.name: InnerErrorToNative_NotificationAndSlot_001
 * @tc.desc: 验证通知管理和 Slot 类的 InnerErrorCode 到 Inner API 错误码映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_NotificationAndSlot_001, TestSize.Level1)
{
    // 通知管理类
    EXPECT_EQ(ERR_ANS_NOTIFICATION_NOT_EXISTS, InnerErrorToNative(ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS));
    EXPECT_EQ(ERR_ANS_NOTIFICATION_IS_UNREMOVABLE, InnerErrorToNative(ERR_ANS_INNER_NOTIFICATION_IS_UNREMOVABLE));
    EXPECT_EQ(ERR_ANS_OVER_MAX_ACTIVE_PERSECOND, InnerErrorToNative(ERR_ANS_INNER_OVER_MAX_ACTIVE_PERSECOND));
    EXPECT_EQ(ERR_ANS_OVER_MAX_UPDATE_PERSECOND, InnerErrorToNative(ERR_ANS_INNER_OVER_MAX_UPDATE_PERSECOND));
    EXPECT_EQ(ERR_ANS_DUPLICATE_MSG, InnerErrorToNative(ERR_ANS_INNER_DUPLICATE_MSG));
    EXPECT_EQ(ERR_ANS_EXPIRED_NOTIFICATION, InnerErrorToNative(ERR_ANS_INNER_EXPIRED_NOTIFICATION));
    EXPECT_EQ(ERR_ANS_REPEAT_CREATE, InnerErrorToNative(ERR_ANS_INNER_REPEAT_CREATE));
    EXPECT_EQ(ERR_ANS_END_NOTIFICATION, InnerErrorToNative(ERR_ANS_INNER_END_NOTIFICATION));
    EXPECT_EQ(ERR_ANS_DIALOG_POP_SUCCEEDED, InnerErrorToNative(ERR_ANS_INNER_DIALOG_POP_SUCCEEDED));

    // Slot 类
    EXPECT_EQ(ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED,
        InnerErrorToNative(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED));
    EXPECT_EQ(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST,
        InnerErrorToNative(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST));
    EXPECT_EQ(ERR_ANS_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED,
        InnerErrorToNative(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_READ_TEMPLATE_CONFIG_FAILED));
    EXPECT_EQ(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED,
        InnerErrorToNative(ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_ENABLED));
}

/**
 * @tc.name: InnerErrorToNative_SpecialGroups_001
 * @tc.desc: 验证分布式、地理围栏、Push、弹窗、加密、代理/扩展类的 Inner 映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_SpecialGroups_001, TestSize.Level1)
{
    // 分布式
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToNative(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_GET_INFO_FAILED,
        InnerErrorToNative(ERR_ANS_INNER_DISTRIBUTED_GET_INFO_FAILED));
    EXPECT_EQ(ERR_ANS_OPERATION_TIMEOUT, InnerErrorToNative(ERR_ANS_INNER_OPERATION_TIMEOUT));

    // 地理围栏
    EXPECT_EQ(ERR_ANS_GEOFENCE_ENABLED, InnerErrorToNative(ERR_ANS_INNER_GEOFENCE_ENABLED));
    EXPECT_EQ(ERR_ANS_GEOFENCE_EXCEEDED, InnerErrorToNative(ERR_ANS_INNER_GEOFENCE_EXCEEDED));
    EXPECT_EQ(ERR_ANS_GEOFENCING_OPERATION_TIMEOUT,
        InnerErrorToNative(ERR_ANS_INNER_GEOFENCING_OPERATION_TIMEOUT));
    EXPECT_EQ(ERR_ANS_ERROR_LOCATION_CLOSED, InnerErrorToNative(ERR_ANS_INNER_ERROR_LOCATION_CLOSED));
    EXPECT_EQ(ERR_ANS_AWARNESS_SUGGESTIONS_CLOSED,
        InnerErrorToNative(ERR_ANS_INNER_AWARNESS_SUGGESTIONS_CLOSED));
    EXPECT_EQ(ERR_ANS_CHECK_WEAK_NETWORK, InnerErrorToNative(ERR_ANS_INNER_CHECK_WEAK_NETWORK));

    // Push
    EXPECT_EQ(ERR_ANS_PUSH_CHECK_FAILED, InnerErrorToNative(ERR_ANS_INNER_PUSH_CHECK_FAILED));
    EXPECT_EQ(ERR_ANS_PUSH_CHECK_UNREGISTERED, InnerErrorToNative(ERR_ANS_INNER_PUSH_CHECK_UNREGISTERED));
    EXPECT_EQ(ERR_ANS_PUSH_CHECK_NETWORK_UNREACHABLE,
        InnerErrorToNative(ERR_ANS_INNER_PUSH_CHECK_NETWORK_UNREACHABLE));

    // 弹窗
    EXPECT_EQ(ERR_ANS_DIALOG_IS_POPPING, InnerErrorToNative(ERR_ANS_INNER_DIALOG_IS_POPPING));

    // 加密
    EXPECT_EQ(ERR_ANS_ENCRYPT_FAIL, InnerErrorToNative(ERR_ANS_INNER_ENCRYPT_FAIL));
    EXPECT_EQ(ERR_ANS_DECRYPT_FAIL, InnerErrorToNative(ERR_ANS_INNER_DECRYPT_FAIL));

    // 代理/扩展
    EXPECT_EQ(ERR_ANS_NO_AGENT_SETTING, InnerErrorToNative(ERR_ANS_INNER_NO_AGENT_SETTING));
    EXPECT_EQ(ERR_ANS_NO_PROFILE_TEMPLATE, InnerErrorToNative(ERR_ANS_INNER_NO_PROFILE_TEMPLATE));
    EXPECT_EQ(ERR_ANS_REJECTED_WITH_DISABLE_NOTIFICATION,
        InnerErrorToNative(ERR_ANS_INNER_REJECTED_WITH_DISABLE_NOTIFICATION));
    EXPECT_EQ(ERR_ANS_NO_CUSTOM_RINGTONE_INFO,
        InnerErrorToNative(ERR_ANS_INNER_NO_CUSTOM_RINGTONE_INFO));
    EXPECT_EQ(ERR_ANS_VOICE_SUMMARY_COUNT_EXCEEDED,
        InnerErrorToNative(ERR_ANS_INNER_VOICE_SUMMARY_COUNT_EXCEEDED));
    EXPECT_EQ(ERR_ANS_DEVICE_NOT_SUPPORT, InnerErrorToNative(ERR_ANS_INNER_DEVICE_NOT_SUPPORT));
    EXPECT_EQ(ERR_ANS_NOT_IMPL_EXTENSIONABILITY,
        InnerErrorToNative(ERR_ANS_INNER_NOT_IMPL_EXTENSIONABILITY));
    EXPECT_EQ(ERR_ANS_DLP_HAP, InnerErrorToNative(ERR_ANS_INNER_DLP_HAP));
    EXPECT_EQ(ERR_ANS_NOTIFICATION_SNOOZE_NOTALLOWED,
        InnerErrorToNative(ERR_ANS_INNER_NOTIFICATION_SNOOZE_NOTALLOWED));
}

/**
 * @tc.name: InnerErrorToNative_UnknownCode_001
 * @tc.desc: 验证未知 InnerErrorCode 返回 ERR_ANS_TASK_ERR
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_UnknownCode_001, TestSize.Level1)
{
    int32_t unknownCode = 999999;
    EXPECT_EQ(ERR_ANS_TASK_ERR, InnerErrorToNative(unknownCode));
}

/**
 * @tc.name: InnerErrorCode_EnumValues_001
 * @tc.desc: 验证 InnerErrorCode 枚举值的正确性
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorCode_EnumValues_001, TestSize.Level1)
{
    // 验证 OK 值
    EXPECT_EQ(0u, ERR_ANS_INNER_OK);

    // 验证分组基值
    EXPECT_EQ(100000u, ERR_ANS_INNER_BASE_INFRA);
    EXPECT_EQ(110000u, ERR_ANS_INNER_BASE_PERMISSION);
    EXPECT_EQ(120000u, ERR_ANS_INNER_BASE_PARAM);
    EXPECT_EQ(130000u, ERR_ANS_INNER_BASE_NOTIFICATION);
    EXPECT_EQ(140000u, ERR_ANS_INNER_BASE_SLOT);
    EXPECT_EQ(150000u, ERR_ANS_INNER_BASE_SUBSCRIBE);
    EXPECT_EQ(160000u, ERR_ANS_INNER_BASE_DISTRIBUTED);
    EXPECT_EQ(170000u, ERR_ANS_INNER_BASE_GEOFENCE);
    EXPECT_EQ(180000u, ERR_ANS_INNER_BASE_PUSH);
    EXPECT_EQ(190000u, ERR_ANS_INNER_BASE_DIALOG);
    EXPECT_EQ(200000u, ERR_ANS_INNER_BASE_ENCRYPT);
    EXPECT_EQ(210000u, ERR_ANS_INNER_BASE_AGENT_EXT);

    // 验证具体枚举值
    EXPECT_EQ(100001u, ERR_ANS_INNER_SERVICE_NOT_READY);
    EXPECT_EQ(110001u, ERR_ANS_INNER_PERMISSION_DENIED);
    EXPECT_EQ(120001u, ERR_ANS_INNER_INVALID_PARAM);
    EXPECT_EQ(130001u, ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
    EXPECT_EQ(140001u, ERR_ANS_INNER_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST);
    EXPECT_EQ(150001u, ERR_ANS_INNER_SUBSCRIBER_IS_DELETING);
    EXPECT_EQ(160001u, ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED);
    EXPECT_EQ(170001u, ERR_ANS_INNER_GEOFENCE_ENABLED);
    EXPECT_EQ(180001u, ERR_ANS_INNER_PUSH_CHECK_FAILED);
    EXPECT_EQ(190001u, ERR_ANS_INNER_DIALOG_IS_POPPING);
    EXPECT_EQ(200001u, ERR_ANS_INNER_ENCRYPT_FAIL);
    EXPECT_EQ(210001u, ERR_ANS_INNER_NO_AGENT_SETTING);
}

/**
 * @tc.name: InnerErrorToExternal_OK_001
 * @tc.desc: 验证 ERR_ANS_INNER_OK (0) 内置处理返回 ERR_OK (0)
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_OK_001, TestSize.Level1)
{
    // ERR_ANS_INNER_OK 内置处理：直接返回 ERR_OK (0)
    EXPECT_EQ(ERR_OK, InnerErrorToExternal(ERR_ANS_INNER_OK));
}

/**
 * @tc.name: InnerErrorToNative_OK_001
 * @tc.desc: 验证 ERR_ANS_INNER_OK (0) 内置处理返回 ERR_OK (0)
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_OK_001, TestSize.Level1)
{
    // ERR_ANS_INNER_OK 内置处理：直接返回 ERR_OK (0)
    EXPECT_EQ(ERR_OK, InnerErrorToNative(ERR_ANS_INNER_OK));
}

// --- GetExternalErrMessage (通过外部错误码获取错误消息) ---

/**
 * @tc.name: GetExternalErrMessage_BasicMapping_001
 * @tc.desc: 验证通过外部错误码获取错误消息的基本映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, GetExternalErrMessage_BasicMapping_001, TestSize.Level1)
{
    // 权限类
    EXPECT_EQ("Permission denied", GetExternalErrMessage(ERROR_PERMISSION_DENIED));
    EXPECT_EQ("Not system application to call the interface",
        GetExternalErrMessage(ERROR_NOT_SYSTEM_APP));
    EXPECT_EQ("Notification disabled", GetExternalErrMessage(ERROR_NOTIFICATION_CLOSED));

    // 参数类
    EXPECT_EQ("Invalid parameter", GetExternalErrMessage(ERROR_PARAM_INVALID));
    EXPECT_EQ("The specified bundle name was not found",
        GetExternalErrMessage(ERROR_BUNDLE_NOT_FOUND));
    EXPECT_EQ("The specified bundle is invalid",
        GetExternalErrMessage(ERROR_BUNDLE_INVALID));

    // 基础设施类
    EXPECT_EQ("Failed to connect to the service",
        GetExternalErrMessage(ERROR_SERVICE_CONNECT_ERROR));
    EXPECT_EQ("Marshalling or unmarshalling error",
        GetExternalErrMessage(ERROR_IPC_ERROR));
    EXPECT_EQ("Memory operation failed",
        GetExternalErrMessage(ERROR_INTERNAL_ERROR));
}

/**
 * @tc.name: GetExternalErrMessage_NotificationAndSpecial_001
 * @tc.desc: 验证通知管理和特殊分组的外部错误码消息映射
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, GetExternalErrMessage_NotificationAndSpecial_001, TestSize.Level1)
{
    // 通知管理类
    EXPECT_EQ("The notification does not exist",
        GetExternalErrMessage(ERROR_NOTIFICATION_NOT_EXIST));
    EXPECT_EQ("Notification deletion disabled",
        GetExternalErrMessage(ERROR_NOTIFICATION_UNREMOVABLE));
    EXPECT_EQ("The notification sending frequency reaches the upper limit",
        GetExternalErrMessage(ERROR_OVER_MAX_NUM_PER_SECOND));
    EXPECT_EQ("The notification version for this update is too low",
        GetExternalErrMessage(ERROR_EXPIRED_NOTIFICATION));
    EXPECT_EQ("Repeat create or end", GetExternalErrMessage(ERROR_REPEAT_SET));

    // Slot 类
    EXPECT_EQ("Failed to read the template configuration",
        GetExternalErrMessage(ERROR_READ_TEMPLATE_CONFIG_FAILED));
    EXPECT_EQ("Notification slot disabled",
        GetExternalErrMessage(ERROR_SLOT_CLOSED));

    // 分布式
    EXPECT_EQ("Distributed operation failed",
        GetExternalErrMessage(ERROR_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ("Distributed operation timeout",
        GetExternalErrMessage(ERROR_DISTRIBUTED_OPERATION_TIMEOUT));

    // 弹窗
    EXPECT_EQ("Dialog is popping", GetExternalErrMessage(ERROR_DIALOG_IS_POPPING));

    // 代理/扩展
    EXPECT_EQ("There is no corresponding agent relationship configuration",
        GetExternalErrMessage(ERROR_NO_AGENT_SETTING));
    EXPECT_EQ("The do-not-disturb profile does not exist",
        GetExternalErrMessage(ERROR_NO_PROFILE_TEMPLATE));
    EXPECT_EQ("The application is not allowed to send notifications due to permission settings",
        GetExternalErrMessage(ERROR_REJECTED_WITH_DISABLE_NOTIFICATION));
    EXPECT_EQ("The specified bundle has no custom ringtone information",
        GetExternalErrMessage(ERROR_NO_CUSTOM_RINGTONE_INFO));
    EXPECT_EQ("SystemCapability not found",
        GetExternalErrMessage(ERROR_SYSTEM_CAP_ERROR));
    EXPECT_EQ("The application does not implement the NotificationSubscriberExtensionAbility",
        GetExternalErrMessage(ERROR_NOT_IMPL_EXTENSIONABILITY));
    EXPECT_EQ("This notification is not supported",
        GetExternalErrMessage(ERR_NOTIFICATION_NOT_SUPPORT));
}

/**
 * @tc.name: GetExternalErrMessage_UnknownCode_001
 * @tc.desc: 验证未知外部错误码返回默认消息
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, GetExternalErrMessage_UnknownCode_001, TestSize.Level1)
{
    int32_t unknownCode = 999999;
    std::string defaultMsg = "Default error message";
    EXPECT_EQ(defaultMsg, GetExternalErrMessage(unknownCode, defaultMsg));
    EXPECT_EQ("", GetExternalErrMessage(unknownCode));  // default defaultMsg is ""
}

// ===== InnerErrorToNative: unified entry (any internal code → inner API code) =====

/**
 * @tc.name: InnerErrorToNative_innerCodePath_001
 * @tc.desc: Verify InnerErrorToNative correctly converts InnerErrorCode to inner API code
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_innerCodePath_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_ANS_PERMISSION_DENIED, InnerErrorToNative(ERR_ANS_INNER_PERMISSION_DENIED));
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, InnerErrorToNative(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_EQ(ERR_ANS_NOTIFICATION_NOT_EXISTS,
        InnerErrorToNative(ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS));
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToNative(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(ERR_ANS_NO_MEMORY, InnerErrorToNative(ERR_ANS_INNER_NO_MEMORY));
}

/**
 * @tc.name: InnerErrorToNative_LegacyCodePath_001
 * @tc.desc: Verify InnerErrorToNative handles legacy ERR_ANS_* codes (from IPC)
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_LegacyCodePath_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_ANS_PERMISSION_DENIED, InnerErrorToNative(ERR_ANS_PERMISSION_DENIED));
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, InnerErrorToNative(ERR_ANS_INVALID_PARAM));
    EXPECT_EQ(ERR_ANS_NO_MEMORY, InnerErrorToNative(ERR_ANS_NO_MEMORY));
    EXPECT_EQ(ERR_ANS_TASK_ERR, InnerErrorToNative(ERR_ANS_TASK_ERR));
    EXPECT_EQ(ERR_ANS_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToNative(ERR_ANS_DISTRIBUTED_OPERATION_FAILED));
}

/**
 * @tc.name: InnerErrorToNative_OkCode_001
 * @tc.desc: Verify that ERR_OK and ERR_ANS_INNER_OK return ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToNative_OkCode_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OK, InnerErrorToNative(ERR_OK));
    EXPECT_EQ(ERR_OK, InnerErrorToNative(ERR_ANS_INNER_OK));
}

// ===== InnerErrorToExternal: unified entry (any internal code → external code) =====

/**
 * @tc.name: InnerErrorToExternal_innerCodePath_001
 * @tc.desc: Verify InnerErrorToExternal correctly converts innerCodes (primary path)
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_innerCodePath_001, TestSize.Level1)
{
    // innerCode primary path
    EXPECT_EQ(ERROR_PERMISSION_DENIED, InnerErrorToExternal(ERR_ANS_INNER_PERMISSION_DENIED));
    EXPECT_EQ(ERROR_PARAM_INVALID, InnerErrorToExternal(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_EQ(ERROR_NOTIFICATION_NOT_EXIST,
        InnerErrorToExternal(ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS));
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToExternal(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_INNER_NO_MEMORY));
}

/**
 * @tc.name: InnerErrorToExternal_OkCode_001
 * @tc.desc: Verify that ERR_OK and ERR_ANS_INNER_OK return ERR_OK directly
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_OkCode_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OK, InnerErrorToExternal(ERR_OK));
    EXPECT_EQ(ERR_OK, InnerErrorToExternal(ERR_ANS_INNER_OK));
}

// ===== InnerErrorToExternal upgraded nativeCode fallback tests =====

/**
 * @tc.name: InnerErrorToExternal_nativeCodeFallback_001
 * @tc.desc: Verify the upgraded InnerErrorToExternal can correctly fall back
 *           to nativeCode lookup (backward-compatible with legacy modules such
 *           as distributed that still return ERR_ANS_* codes)
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_nativeCodeFallback_001, TestSize.Level1)
{
    // Legacy codes from the distributed module — should now convert correctly
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToExternal(ERR_ANS_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_FAILED,
        InnerErrorToExternal(ERR_ANS_DISTRIBUTED_GET_INFO_FAILED));
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_TIMEOUT,
        InnerErrorToExternal(ERR_ANS_OPERATION_TIMEOUT));

    // Legacy codes from the infrastructure module
    EXPECT_EQ(ERROR_PARAM_INVALID, InnerErrorToExternal(ERR_ANS_INVALID_PARAM));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_NO_MEMORY));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, InnerErrorToExternal(ERR_ANS_TASK_ERR));

    // Additional legacy codes (merged from duplicate test)
    EXPECT_EQ(ERROR_NOTIFICATION_CLOSED, InnerErrorToExternal(ERR_ANS_NOT_ALLOWED));
    EXPECT_EQ(ERROR_DIALOG_IS_POPPING, InnerErrorToExternal(ERR_ANS_DIALOG_IS_POPPING));
}

/**
 * @tc.name: InnerErrorToExternal_AmbiguousCode_001
 * @tc.desc: Verify that a SVC code and its corresponding Inner code map to the
 *           same external code (both paths produce the same result)
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, InnerErrorToExternal_AmbiguousCode_001, TestSize.Level1)
{
    // Each (SVC, Inner) pair must map to the same External code
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_PERMISSION_DENIED),
        InnerErrorToExternal(ERR_ANS_PERMISSION_DENIED));
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_INVALID_PARAM),
        InnerErrorToExternal(ERR_ANS_INVALID_PARAM));
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED),
        InnerErrorToExternal(ERR_ANS_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_DIALOG_IS_POPPING),
        InnerErrorToExternal(ERR_ANS_DIALOG_IS_POPPING));
}

// ===== Round-trip consistency tests =====

/**
 * @tc.name: RoundTrip_InnerErrorToNativeThenInnerErrorToExternal_001
 * @tc.desc: Verify InnerErrorToNative → InnerErrorToExternal produces the same
 *           result as InnerErrorToExternal (direct nativeCode lookup)
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, RoundTrip_InnerErrorToNativeThenInnerErrorToExternal_001, TestSize.Level1)
{
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_DISTRIBUTED_OPERATION_FAILED),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_DISTRIBUTED_OPERATION_FAILED)));

    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_PERMISSION_DENIED),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_PERMISSION_DENIED)));

    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_NO_MEMORY),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_NO_MEMORY)));

    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_DIALOG_IS_POPPING),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_DIALOG_IS_POPPING)));
}

/**
 * @tc.name: RoundTrip_ServiceToInnerThenInnerErrorToExternal_001
 * @tc.desc: Verify ServiceToInner → InnerErrorToExternal produces the same
 *           result as InnerErrorToExternal
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, RoundTrip_ServiceToInnerThenInnerErrorToExternal_001, TestSize.Level1)
{
    // Both paths must produce the same External code
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED)));

    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_PERMISSION_DENIED),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_INNER_PERMISSION_DENIED)));

    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_NO_MEMORY),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_INNER_NO_MEMORY)));

    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_DIALOG_IS_POPPING),
        InnerErrorToExternal(InnerErrorToNative(ERR_ANS_INNER_DIALOG_IS_POPPING)));
}

// ===== GetInnerErrMessage =====

/**
 * @tc.name: GetInnerErrMessage_InnerCodeMatch_001
 * @tc.desc: 验证通过 InnerErrorCode 获取错误消息
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, GetInnerErrMessage_InnerCodeMatch_001, TestSize.Level1)
{
    EXPECT_EQ("Permission denied", GetInnerErrMessage(ERR_ANS_INNER_PERMISSION_DENIED));
    EXPECT_EQ("Not system application to call the interface",
        GetInnerErrMessage(ERR_ANS_INNER_NON_SYSTEM_APP));
    EXPECT_EQ("Invalid parameter", GetInnerErrMessage(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_EQ("Failed to connect to the service",
        GetInnerErrMessage(ERR_ANS_INNER_SERVICE_NOT_READY));
    EXPECT_EQ("The notification does not exist",
        GetInnerErrMessage(ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS));
    EXPECT_EQ("Distributed operation failed",
        GetInnerErrMessage(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ("Dialog is popping", GetInnerErrMessage(ERR_ANS_INNER_DIALOG_IS_POPPING));
    EXPECT_EQ("Geofencing disabled", GetInnerErrMessage(ERR_ANS_INNER_GEOFENCE_ENABLED));
    EXPECT_EQ("No permission", GetInnerErrMessage(ERR_ANS_INNER_PUSH_CHECK_FAILED));
    EXPECT_EQ("SystemCapability not found", GetInnerErrMessage(ERR_ANS_INNER_DEVICE_NOT_SUPPORT));
    EXPECT_EQ("Invalid operation", GetInnerErrMessage(ERR_ANS_INNER_INVALID_OPERATION));
}

/**
 * @tc.name: GetInnerErrMessage_NativeCodeMatch_001
 * @tc.desc: 验证通过 nativeCode (ERR_ANS_*) 获取错误消息
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, GetInnerErrMessage_NativeCodeMatch_001, TestSize.Level1)
{
    EXPECT_EQ("Permission denied", GetInnerErrMessage(ERR_ANS_PERMISSION_DENIED));
    EXPECT_EQ("Invalid parameter", GetInnerErrMessage(ERR_ANS_INVALID_PARAM));
    EXPECT_EQ("Failed to connect to the service",
        GetInnerErrMessage(ERR_ANS_SERVICE_NOT_READY));
    EXPECT_EQ("The notification does not exist",
        GetInnerErrMessage(ERR_ANS_NOTIFICATION_NOT_EXISTS));
    EXPECT_EQ("Distributed operation failed",
        GetInnerErrMessage(ERR_ANS_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ("Dialog is popping", GetInnerErrMessage(ERR_ANS_DIALOG_IS_POPPING));
    EXPECT_EQ("No permission", GetInnerErrMessage(ERR_ANS_PUSH_CHECK_FAILED));
    EXPECT_EQ("SystemCapability not found", GetInnerErrMessage(ERR_ANS_DEVICE_NOT_SUPPORT));
}

/**
 * @tc.name: GetInnerErrMessage_UnknownCode_001
 * @tc.desc: 验证未知错误码返回默认消息
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, GetInnerErrMessage_UnknownCode_001, TestSize.Level1)
{
    int32_t unknownCode = 999999;
    std::string customMsg = "Custom default message";
    EXPECT_EQ(customMsg, GetInnerErrMessage(unknownCode, customMsg));
    EXPECT_EQ("", GetInnerErrMessage(unknownCode));
}

// ===== NativeErrorToExternal =====

/**
 * @tc.name: NativeErrorToExternal_OkCode_001
 * @tc.desc: 验证 ERR_OK 返回 ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, NativeErrorToExternal_OkCode_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OK, NativeErrorToExternal(ERR_OK));
    EXPECT_EQ(ERR_OK, NativeErrorToExternal(ERR_ANS_INNER_OK));
}

/**
 * @tc.name: NativeErrorToExternal_NativeCodeLookup_001
 * @tc.desc: 验证通过 nativeCode 查找返回正确的外部错误码
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, NativeErrorToExternal_NativeCodeLookup_001, TestSize.Level1)
{
    EXPECT_EQ(ERROR_PERMISSION_DENIED, NativeErrorToExternal(ERR_ANS_PERMISSION_DENIED));
    EXPECT_EQ(ERROR_PARAM_INVALID, NativeErrorToExternal(ERR_ANS_INVALID_PARAM));
    EXPECT_EQ(ERROR_NOT_SYSTEM_APP, NativeErrorToExternal(ERR_ANS_NON_SYSTEM_APP));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, NativeErrorToExternal(ERR_ANS_NO_MEMORY));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, NativeErrorToExternal(ERR_ANS_TASK_ERR));
    EXPECT_EQ(ERROR_NOTIFICATION_NOT_EXIST,
        NativeErrorToExternal(ERR_ANS_NOTIFICATION_NOT_EXISTS));
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_FAILED,
        NativeErrorToExternal(ERR_ANS_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(ERROR_DIALOG_IS_POPPING, NativeErrorToExternal(ERR_ANS_DIALOG_IS_POPPING));
    EXPECT_EQ(ERROR_NOTIFICATION_CLOSED, NativeErrorToExternal(ERR_ANS_NOT_ALLOWED));
}

/**
 * @tc.name: NativeErrorToExternal_InnerCodeLookup_001
 * @tc.desc: 验证通过 InnerErrorCode 查找返回正确的外部错误码
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, NativeErrorToExternal_InnerCodeLookup_001, TestSize.Level1)
{
    EXPECT_EQ(ERROR_PERMISSION_DENIED,
        NativeErrorToExternal(ERR_ANS_INNER_PERMISSION_DENIED));
    EXPECT_EQ(ERROR_PARAM_INVALID, NativeErrorToExternal(ERR_ANS_INNER_INVALID_PARAM));
    EXPECT_EQ(ERROR_INTERNAL_ERROR, NativeErrorToExternal(ERR_ANS_INNER_TASK_ERR));
    EXPECT_EQ(ERROR_DISTRIBUTED_OPERATION_FAILED,
        NativeErrorToExternal(ERR_ANS_INNER_DISTRIBUTED_OPERATION_FAILED));
    EXPECT_EQ(ERROR_DIALOG_IS_POPPING,
        NativeErrorToExternal(ERR_ANS_INNER_DIALOG_IS_POPPING));
}

/**
 * @tc.name: NativeErrorToExternal_UnknownCode_001
 * @tc.desc: 验证未知错误码直接透传原值
 * @tc.type: FUNC
 */
HWTEST_F(AnsServiceErrorsTest, NativeErrorToExternal_UnknownCode_001, TestSize.Level1)
{
    int32_t unknownCode = 999999;
    EXPECT_EQ(unknownCode, NativeErrorToExternal(unknownCode));
}
