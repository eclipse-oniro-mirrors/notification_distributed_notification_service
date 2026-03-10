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

#include "notification_parameters.h"
#include "ans_log_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace Notification {

void NotificationParameters::SetWantAction(const std::string &action)
{
    wantAction_ = action;
}

std::string NotificationParameters::GetWantAction() const
{
    return wantAction_;
}

void NotificationParameters::SetWantUri(const std::string &uri)
{
    wantUri_ = uri;
}

std::string NotificationParameters::GetWantUri() const
{
    return wantUri_;
}

void NotificationParameters::SetWantParameters(const std::shared_ptr<AAFwk::WantParams> parameters)
{
    wantParameters_ = parameters;
}

const std::shared_ptr<AAFwk::WantParams> NotificationParameters::GetWantParameters() const
{
    return wantParameters_;
}

std::string NotificationParameters::Dump()
{
    std::string wantParametersStr{"null"};
    if (wantParameters_ != nullptr) {
        AAFwk::WantParamWrapper wWrapper(*wantParameters_);
        wantParametersStr = wWrapper.ToString();
    }

    return "NotificationParameters{ wantAction = " + wantAction_ + ", wantUri = " + wantUri_
        + ", wantParameters = " + wantParametersStr + " }";
}

bool NotificationParameters::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(wantAction_)) {
        ANS_LOGE("Failed to write wantAction");
        return false;
    }

    if (!parcel.WriteString(wantUri_)) {
        ANS_LOGE("Failed to write wantUri");
        return false;
    }

    bool hasWantParams = (wantParameters_ != nullptr);
    if (!parcel.WriteBool(hasWantParams)) {
        ANS_LOGE("Failed to write hasWantParams");
        return false;
    }

    if (hasWantParams) {
        if (!parcel.WriteParcelable(wantParameters_.get())) {
            ANS_LOGE("Failed to write wantParameters");
            return false;
        }
    }

    return true;
}

NotificationParameters *NotificationParameters::Unmarshalling(Parcel &parcel)
{
    auto parameters = new (std::nothrow) NotificationParameters();
    if (parameters && !parameters->ReadFromParcel(parcel)) {
        ANS_LOGE("Failed to create NotificationParameters");
        delete parameters;
        parameters = nullptr;
    }

    return parameters;
}

bool NotificationParameters::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(wantAction_)) {
        ANS_LOGE("Failed to read wantAction");
        return false;
    }

    if (!parcel.ReadString(wantUri_)) {
        ANS_LOGE("Failed to read wantUri");
        return false;
    }

    bool hasWantParams = false;
    if (!parcel.ReadBool(hasWantParams)) {
        ANS_LOGE("Failed to read hasWantParams");
        return false;
    }

    if (hasWantParams) {
        wantParameters_ = std::shared_ptr<AAFwk::WantParams>(parcel.ReadParcelable<AAFwk::WantParams>());
        if (!wantParameters_) {
            ANS_LOGE("Failed to read wantParameters");
            return false;
        }
    }

    return true;
}
}  // namespace Notification
}  // namespace OHOS