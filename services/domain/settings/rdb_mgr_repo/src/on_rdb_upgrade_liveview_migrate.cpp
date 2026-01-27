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

#include "rdb_hooks.h"

#include "ans_log_wrapper.h"
#include "aes_gcm_helper.h"
#include "nlohmann/json.hpp"
#include "notification_content.h"

namespace OHOS::Notification::Domain {
static bool UpdateContentByJsonObject(nlohmann::json &jsonObject, const std::string &wantAgent)
{
    if (jsonObject.find("content") == jsonObject.cend()) {
        ANS_LOGW("Invalid content json - missing content field");
        return false;
    }

    auto contentObj = jsonObject.at("content");
    if (contentObj.is_null() || !contentObj.is_object()) {
        ANS_LOGE("Invalid content object");
        return false;
    }

    if (!contentObj.contains("contentType")) {
        ANS_LOGE("Missing contentType in content");
        return false;
    }

    auto contentType = contentObj.at("contentType");
    if (!contentType.is_number_integer()) {
        ANS_LOGE("ContentType is not integer");
        return false;
    }

    if (static_cast<NotificationContent::Type>(contentType.get<int32_t>()) !=
        NotificationContent::Type::LIVE_VIEW) {
        ANS_LOGE("ContentType is not live view");
        return false;
    }

    if (!contentObj.contains("content")) {
        ANS_LOGE("Missing nested content field");
        return false;
    }

    auto liveviewObj = contentObj.at("content");
    if (liveviewObj.is_null()) {
        ANS_LOGE("Cannot convert liveview content from JSON");
        return false;
    }

    liveviewObj["extensionWantAgent"] = wantAgent;
    contentObj["content"] = liveviewObj;
    jsonObject["content"] = contentObj;

    ANS_LOGD("UpdateContentByJsonObject succeeded with wantAgent: %{public}s",
        wantAgent.c_str());
    return true;
}

static bool UpdateRequestByJsonObject(nlohmann::json &jsonObject)
{
    if (jsonObject.is_null() || !jsonObject.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return false;
    }

    if (!jsonObject.contains("actionButtons") || jsonObject.at("actionButtons").empty() ||
        !jsonObject.at("actionButtons").is_array()) {
        ANS_LOGW("Invalid or missing action button json");
        return false;
    }

    nlohmann::json extentionWantAgent;
    nlohmann::json buttonJson = nlohmann::json::array();
    auto buttonArray = jsonObject.at("actionButtons");

    for (uint32_t i = 0; i < buttonArray.size(); i++) {
        if (i == 0) {
            extentionWantAgent = buttonArray[i];
            continue;
        }
        buttonJson.push_back(buttonArray[i]);
    }

    if (extentionWantAgent.find("wantAgent") == extentionWantAgent.cend() ||
        !extentionWantAgent.at("wantAgent").is_string()) {
        ANS_LOGW("Invalid want agent in action button");
        return false;
    }

    std::string wantString = extentionWantAgent.at("wantAgent").get<std::string>();
    if (!UpdateContentByJsonObject(jsonObject, wantString)) {
        return false;
    }

    jsonObject["actionButtons"] = buttonJson;
    return true;
}

bool OnRdbUpgradeLiveviewMigrate(const std::string &oldValue, std::string &newValue)
{
    // Decrypt the value
    std::string decryptedValue;
    AesGcmHelper::Decrypt(decryptedValue, oldValue);
    // Parse JSON
    nlohmann::json jsonObject = nlohmann::json::parse(decryptedValue);
    if (!UpdateRequestByJsonObject(jsonObject)) {
        ANS_LOGE("UpdateRequestByJsonObject failed");
        return false;
    }
    // Encrypt the updated value
    AesGcmHelper::Encrypt(jsonObject.dump(), newValue);
    return true; // Indicate successful migration
}
}