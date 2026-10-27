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

#include "notification_classification.h"

#include "ans_log_wrapper.h"
#include "string_ex.h"

#include <cinttypes>
#include <string>

namespace OHOS {
namespace Notification {
namespace {
constexpr size_t PRIORITY_NOTIFICATION_TYPE_MAX_LENGTH = 256;

bool IsValidPrioritySource(int32_t source)
{
    return source >= static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN) &&
        source <= static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE);
}
}  // namespace

NotificationClassification::NotificationClassification(const std::string &classification,
    const std::string &subClassification)
    : classification_(classification), subClassification_(subClassification), classificationSet_(true)
{}

void NotificationClassification::SetClassification(const std::string &classification)
{
    classification_ = classification;
    classificationSet_ = true;
}

std::string NotificationClassification::GetClassification() const
{
    return classification_;
}

void NotificationClassification::SetSubClassification(const std::string &subClassification)
{
    subClassification_ = subClassification;
    classificationSet_ = true;
}

std::string NotificationClassification::GetSubClassification() const
{
    return subClassification_;
}

bool NotificationClassification::IsClassificationSet() const
{
    return classificationSet_;
}

bool NotificationClassification::IsPriorityInfoSet() const
{
    return priorityInfoSet_;
}

std::string NotificationClassification::Dump()
{
    return "NotificationClassification{ "
        "classification = " + classification_ +
        ", subClassification = " + subClassification_ +
        ", " + priorityInfo_.Dump() +
        ", classificationSet = " + (classificationSet_ ? "true" : "false") +
        ", priorityInfoSet = " + (priorityInfoSet_ ? "true" : "false") +
        " }";
}

bool NotificationClassification::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(classification_)) {
        ANS_LOGE("Failed to write classification");
        return false;
    }

    if (!parcel.WriteString(subClassification_)) {
        ANS_LOGE("Failed to write subClassification");
        return false;
    }

    if (!priorityInfo_.Marshalling(parcel)) {
        ANS_LOGE("Failed to write priorityInfo");
        return false;
    }

    if (!parcel.WriteBool(classificationSet_)) {
        ANS_LOGE("Failed to write classificationSet");
        return false;
    }

    if (!parcel.WriteBool(priorityInfoSet_)) {
        ANS_LOGE("Failed to write priorityInfoSet");
        return false;
    }

    return true;
}

NotificationClassification *NotificationClassification::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) NotificationClassification();
    if ((objptr != nullptr) && !objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

void NotificationClassification::PriorityInfo::SetPriorityNotificationType(const std::string &priorityNotificationType)
{
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    priorityNotificationType_ = priorityNotificationType;
#endif
}

std::string NotificationClassification::PriorityInfo::GetPriorityNotificationType() const
{
    return priorityNotificationType_;
}

void NotificationClassification::PriorityInfo::SetExpiredTime(int64_t expiredTime)
{
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    expiredTime_ = expiredTime;
#endif
}

int64_t NotificationClassification::PriorityInfo::GetExpiredTime() const
{
    return expiredTime_;
}

void NotificationClassification::PriorityInfo::SetSource(int32_t source)
{
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    if (source >= static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN) &&
        source <= static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE)) {
        source_ = source;
        return;
    }
    ANS_LOGW("Invalid priority source %{public}d, keep current value instead", source);
#endif
}

int32_t NotificationClassification::PriorityInfo::GetSource() const
{
    return source_;
}

std::string NotificationClassification::PriorityInfo::Dump()
{
    return "priorityNotificationType = " + priorityNotificationType_ +
        ", expiredTime = " + std::to_string(expiredTime_) +
        ", source = " + std::to_string(source_);
}

bool NotificationClassification::PriorityInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(priorityNotificationType_)) {
        ANS_LOGE("Failed to write priorityNotificationType");
        return false;
    }

    if (!parcel.WriteInt64(expiredTime_)) {
        ANS_LOGE("Failed to write expiredTime");
        return false;
    }

    if (!parcel.WriteInt32(source_)) {
        ANS_LOGE("Failed to write source");
        return false;
    }

    return true;
}

bool NotificationClassification::PriorityInfo::ReadFromParcel(Parcel &parcel)
{
    std::string priorityNotificationType;
    int64_t expiredTime = 0;
    int32_t source = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT);
    if (!parcel.ReadString(priorityNotificationType) || !parcel.ReadInt64(expiredTime) ||
        !parcel.ReadInt32(source)) {
        ANS_LOGW("NotificationClassification::PriorityInfo::ReadFromParcel read priorityInfo failed, "
            "old format parcel without priorityInfo tail fields, use default values");
        return true;
    }

    if (expiredTime < 0) {
        ANS_LOGW("Invalid expiredTime %{public}" PRId64 " from parcel, use 0 instead", expiredTime);
        expiredTime = 0;
    }
    if (!IsValidPrioritySource(source)) {
        ANS_LOGW("Invalid priority source %{public}d from parcel, use INVALID_RESULT instead", source);
        source = static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT);
    }
    if (priorityNotificationType.size() > PRIORITY_NOTIFICATION_TYPE_MAX_LENGTH) {
        ANS_LOGW("Priority notification type too long (%{public}zu), keep the default type instead",
            priorityNotificationType.size());
        priorityNotificationType = NotificationConstant::PriorityNotificationType::OTHER;
    }
    priorityNotificationType_ = priorityNotificationType;
    expiredTime_ = expiredTime;
    source_ = source;
    return true;
}

void NotificationClassification::SetPriorityInfo(const PriorityInfo &priorityInfo)
{
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    priorityInfo_ = priorityInfo;
    priorityInfoSet_ = true;
#endif
}

const NotificationClassification::PriorityInfo &NotificationClassification::GetPriorityInfo() const
{
    return priorityInfo_;
}

bool NotificationClassification::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(classification_)) {
        ANS_LOGE("Failed to read classification");
        return false;
    }

    if (!parcel.ReadString(subClassification_)) {
        ANS_LOGE("Failed to read subClassification");
        return false;
    }

    priorityInfo_.ReadFromParcel(parcel);

    bool classificationSet = false;
    bool priorityInfoSet = false;
    if (!parcel.ReadBool(classificationSet) || !parcel.ReadBool(priorityInfoSet)) {
        ANS_LOGW("NotificationClassification::ReadFromParcel read dimension flags failed, "
            "old format parcel without the flag tail fields, keep both dimensions unset");
        return true;
    }
    classificationSet_ = classificationSet;
    priorityInfoSet_ = priorityInfoSet;

    return true;
}
}  // namespace Notification
}  // namespace OHOS