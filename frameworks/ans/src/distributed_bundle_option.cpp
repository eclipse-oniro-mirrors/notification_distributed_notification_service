/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "distributed_bundle_option.h"
#include <string>
#include "ans_log_wrapper.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
DistributedBundleOption::DistributedBundleOption(std::shared_ptr<NotificationBundleOption> &bundle, const bool enable)
    : bundle_(bundle), enable_(enable)
{}

DistributedBundleOption::~DistributedBundleOption()
{}

std::shared_ptr<NotificationBundleOption> DistributedBundleOption::GetBundle() const
{
    return bundle_;
}

void DistributedBundleOption::SetBundle(std::shared_ptr<NotificationBundleOption> bundle)
{
    bundle_ = bundle;
}

bool DistributedBundleOption::isEnable() const
{
    return enable_;
}

void DistributedBundleOption::SetEnable(const bool& enable)
{
    enable_ = enable;
}

std::string DistributedBundleOption::Dump()
{
    return "DistributedBundleOption{ "
            "bundleName = " +(bundle_ ? bundle_->GetBundleName() : "null")  +
            ", uid = " + (bundle_ ? std::to_string(bundle_->GetUid()) : "null") +
            ", enable = " + std::to_string(enable_) +
            " }";
}

bool DistributedBundleOption::Marshalling(Parcel &parcel) const
{
    bool valid {false};
    valid = bundle_ ? true : false;
    if (!parcel.WriteBool(valid)) {
        ANS_LOGE("Failed to write the flag which indicate whether bundle is null");
        return false;
    }

    if (valid) {
        if (!parcel.WriteParcelable(bundle_.get())) {
            ANS_LOGE("Failed to write bundle");
            return false;
        }
    }

    if (!parcel.WriteBool(enable_)) {
        ANS_LOGE("Failed to write enable");
        return false;
    }

    return true;
}

DistributedBundleOption *DistributedBundleOption::Unmarshalling(Parcel &parcel)
{
    auto pDistributedBundleOption = new (std::nothrow) DistributedBundleOption();
    if (pDistributedBundleOption && !pDistributedBundleOption->ReadFromParcel(parcel)) {
        delete pDistributedBundleOption;
        pDistributedBundleOption = nullptr;
    }

    return pDistributedBundleOption;
}

bool DistributedBundleOption::ReadFromParcel(Parcel &parcel)
{
    bool valid {false};

    valid = parcel.ReadBool();
    if (valid) {
        bundle_ = std::shared_ptr<NotificationBundleOption>(parcel.ReadParcelable<NotificationBundleOption>());
        if (!bundle_) {
            ANS_LOGE("Failed to read bundle");
            return false;
        }
    }

    enable_ = parcel.ReadBool();

    return true;
}

bool DistributedBundleOption::ToJson(nlohmann::json &jsonObject) const
{
    if (bundle_ != nullptr) {
        nlohmann::json bundleOptionObj;
        if (!NotificationJsonConverter::ConvertToJson(bundle_.get(), bundleOptionObj)) {
            ANS_LOGE("Cannot convert notificationBundleOption to JSON.");
            return false;
        }
        jsonObject["bundle"] = bundleOptionObj;
    }

    jsonObject["enable"] = enable_;
    return true;
}

DistributedBundleOption *DistributedBundleOption::FromJson(const nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() or !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return nullptr;
    }

    auto *pDistributedBundleOption = new (std::nothrow) DistributedBundleOption();
    if (pDistributedBundleOption == nullptr) {
        ANS_LOGE("null pDistributedBundleOption");
        return nullptr;
    }

    const auto &jsonEnd = jsonObject.cend();

    if (jsonObject.find("bundle") != jsonEnd) {
        auto bundleOptionObj = jsonObject.at("bundle");
        if (!bundleOptionObj.is_null()) {
            auto *pBundleOption = NotificationJsonConverter::ConvertFromJson<NotificationBundleOption>(bundleOptionObj);
            if (pBundleOption == nullptr) {
                ANS_LOGE("null pBundleOption");
                return nullptr;
            }

            pDistributedBundleOption->bundle_ = std::shared_ptr<NotificationBundleOption>(pBundleOption);
        }
    }

    if (jsonObject.find("enable") != jsonEnd && jsonObject.at("enable").is_boolean()) {
        pDistributedBundleOption->enable_ = jsonObject.at("enable").get<bool>();
    }
    return pDistributedBundleOption;
}

}  // namespace Notification
}  // namespace OHOS