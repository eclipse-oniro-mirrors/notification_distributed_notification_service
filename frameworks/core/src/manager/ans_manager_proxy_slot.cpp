/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <unistd.h>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
const static int MAX_SLOT_FLAGS = 0b111111;
ErrCode AnsManagerProxy::AddSlotByType(NotificationConstant::SlotType slotType)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[AddSlotByType] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotType)) {
        ANS_LOGE("[AddSlotByType] fail:: write slotIds failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ADD_SLOT_BY_TYPE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[AddSlotByType] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[AddSlotByType] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::AddSlots(const std::vector<sptr<NotificationSlot>> &slots)
{
    if (slots.empty()) {
        ANS_LOGE("[AddSlots] fail: slots is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    size_t slotsSize = slots.size();
    if (slotsSize > MAX_SLOT_NUM) {
        ANS_LOGE("[AddSlots] fail: slotsSize over max size.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[AddSlots] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!WriteParcelableVector(slots, data)) {
        ANS_LOGE("[AddSlots] fail: write slots failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ADD_SLOTS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[AddSlots] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[AddSlots] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::RemoveSlotByType(const NotificationConstant::SlotType &slotType)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[RemoveSlotByType] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotType)) {
        ANS_LOGE("[RemoveSlotByType] fail:: write slotIds failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_SLOT_BY_TYPE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RemoveSlotByType] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[RemoveSlotByType] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::RemoveAllSlots()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[RemoveAllSlots] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_ALL_SLOTS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[RemoveAllSlots] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[RemoveAllSlots] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetSlotByType(const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSlotByType] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotType)) {
        ANS_LOGE("[GetSlotByType] fail:: write slotId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SLOT_BY_TYPE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetSlotByType] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetSlotByType] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        slot = reply.ReadParcelable<NotificationSlot>();
        if (slot == nullptr) {
            ANS_LOGE("[GetSlotByType] slot is null");
        }
    }

    return result;
}

ErrCode AnsManagerProxy::GetSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSlots] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SLOTS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetSlots] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!ReadParcelableVector(slots, reply, result)) {
        ANS_LOGE("[GetSlots] fail: read slots failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetSlotNumAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint64_t &num)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[GetSlotNumAsBundle] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSlotNumAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[GetSlotNumAsBundle] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SLOT_NUM_AS_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadUint64(num)) {
        ANS_LOGE("[GetShowBadgeEnabledForBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetSlotsByBundle(
    const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[GetSlotsByBundle] fail: bundleOption is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSlotsByBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[GetSlotsByBundle] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SLOTS_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetSlotsByBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!ReadParcelableVector(slots, reply, result)) {
        ANS_LOGE("[GetSlotsByBundle] fail: read slots failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetSlotByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[GetSlotByBundle] fail: bundleOption is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSlotByBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[GetSlotByBundle] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotType)) {
        ANS_LOGE("[GetSlotByBundle] fail:: write slotId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SLOT_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetSlotByBundle] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetSlotByBundle] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        slot = reply.ReadParcelable<NotificationSlot>();
        if (slot == nullptr) {
            ANS_LOGE("[GetSlotByBundle] slot is null");
        }
    }

    return result;
}

ErrCode AnsManagerProxy::UpdateSlots(
    const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[UpdateSlots] fail: bundleOption is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (slots.empty()) {
        ANS_LOGE("[UpdateSlots] fail: slots is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    size_t slotSize = slots.size();
    if (slotSize > MAX_SLOT_NUM) {
        ANS_LOGE("[UpdateSlots] fail: slotSize over max size.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[UpdateSlots] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[UpdateSlots] fail:: write bundleoption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!WriteParcelableVector(slots, data)) {
        ANS_LOGE("[UpdateSlots] fail: write slots failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::UPDATE_SLOTS, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[UpdateSlots] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[UpdateSlots] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotType)) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail:: write slotType failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(enabled)) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail: write enabled failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteBool(isForceControl)) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail: write isForceControl failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_ENABLED_FOR_BUNDLE_SLOT, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetEnabledForBundleSlot] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetEnabledForBundleSlot(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[GetEnabledForBundleSlot] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetEnabledForBundleSlot] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[GetEnabledForBundleSlot] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotType)) {
        ANS_LOGE("[GetEnabledForBundleSlot] fail:: write slotType failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ENABLED_FOR_BUNDLE_SLOT, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetEnabledForBundleSlot] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetEnabledForBundleSlot] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[GetEnabledForBundleSlot] fail: read enable failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetEnabledForBundleSlotSelf] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotType)) {
        ANS_LOGE("[GetEnabledForBundleSlotSelf] fail:: write slotType failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ENABLED_FOR_BUNDLE_SLOT_SELF, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetEnabledForBundleSlotSelf] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetEnabledForBundleSlotSelf] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(enabled)) {
        ANS_LOGE("[GetEnabledForBundleSlotSelf] fail: read enable failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,  uint32_t& slotFlags)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[GetSlotFlagsAsBundle] fail: bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetSlotFlagsAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteStrongParcelable(bundleOption)) {
        ANS_LOGE("[GetSlotFlagsAsBundle] fail:: write bundle failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(slotFlags)) {
        ANS_LOGE("[GetSlotFlagsAsBundle] fail: write slots failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_SLOTFLAGS_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadUint32(slotFlags)) {
        ANS_LOGE("[GetSlotFlagsAsBundle] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetNotificationSettings(uint32_t& slotFlags)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetNotificationSettings] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_NOTIFICATION_SETTING, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadUint32(slotFlags)) {
        ANS_LOGE("[GetNotificationSettings] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,  uint32_t slotFlags)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("[SetSlotFlagsAsBundle] fail: bundleOption is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (slotFlags > MAX_SLOT_FLAGS) {
        ANS_LOGE("[SetSlotFlagsAsBundle] fail: Invalid slotFlags.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetSlotFlagsAsBundle] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(bundleOption)) {
        ANS_LOGE("[SetSlotFlagsAsBundle] fail:: write bundleoption failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    // got the LSB 6 bits as slotflags;
    uint32_t validSlotFlag = MAX_SLOT_FLAGS & slotFlags;
    if (!data.WriteInt32(validSlotFlag)) {
        ANS_LOGE("[SetSlotFlagsAsBundle] fail: write slots failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_SYNC };
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_SLOTFLAGS_BY_BUNDLE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}
}  // namespace Notification
}  // namespace OHOS
