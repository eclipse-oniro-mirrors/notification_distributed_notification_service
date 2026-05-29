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

#include <string>

namespace OHOS {
namespace Notification {
NotificationClassification::NotificationClassification(const std::string &classification,
    const std::string &subClassification)
    : classification_(classification), subClassification_(subClassification)
{}

void NotificationClassification::SetClassification(const std::string &classification)
{
    classification_ = classification;
}

std::string NotificationClassification::GetClassification() const
{
    return classification_;
}

void NotificationClassification::SetSubClassification(const std::string &subClassification)
{
    subClassification_ = subClassification;
}

std::string NotificationClassification::GetSubClassification() const
{
    return subClassification_;
}

std::string NotificationClassification::Dump()
{
    return "NotificationClassification{ "
        "classification = " + classification_ +
        ", subClassification = " + subClassification_ +
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

    return true;
}
}  // namespace Notification
}  // namespace OHOS