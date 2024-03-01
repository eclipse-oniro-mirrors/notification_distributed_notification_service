/*
* Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <memory>
#include <cstdio>
#include <cstring>
#include <map>
#include <sys/stat.h>
#include <libxml/globals.h>
#include <libxml/xmlstring.h>
#include "ans_log_wrapper.h"
#include "notification_constant.h"
#include "notification_config_parse.h"

namespace OHOS {
namespace Notification {
NotificationConfigFile::NotificationConfigFile()
{}

NotificationConfigFile::NotificationConfigFile(const std::string &filePath)
{}

NotificationConfigFile::~NotificationConfigFile()
{}

int NotificationConfigFile::binaryToDecimal(const char *binaryString)
{
    int lenth = strlen(binaryString);
    int decimal = 0;
    int weight = 1;

    for (int i = lenth - 1; i >= 0; i--) {
        if (binaryString[i] == '1') {
            decimal += weight;
        }
        weight *= NotificationConstant::DECIMAL_BASE;
    }
    return decimal;
}

void NotificationConfigFile::getDefaultSlotFlagsMap(std::map<std::string, uint32_t> &slotFlagsMap)
{
    // Each bit indicate one reminder way as follows: bit0: Ring, bit1: LockScreen(include AOD), bit2: Banner,
    // bit3: Light, bit4: Vibration.
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION], 0b11111));
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::SERVICE_REMINDER], 0b11011));
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::CONTENT_INFORMATION], 0b00000));
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::OTHER], 0b00000));
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::CUSTOM], 0b00000));
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::LIVE_VIEW], 0b11011));
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::CUSTOMER_SERVICE], 0b10001));
    slotFlagsMap.insert(std::make_pair(NotificationConstant::SLOTTYPECCMNAMES[
        NotificationConstant::SlotType::EMERGENCY_INFORMATION], 0b11111));
    for (auto &iter : slotFlagsMap) {
        ANS_LOGD("Default Got slotFlagsMap item slotType = %{public}s, slotFlags = %{public}d\n",
            iter.first.c_str(), iter.second);
    }
}

bool NotificationConfigFile::parseNotificationConfigCcmFile(
    std::string &filePath, std::map<std::string, uint32_t> &slotFlagsMap)
{
    xmlDocPtr docPtr = xmlReadFile(filePath.c_str(), nullptr, XML_PARSE_NOBLANKS);
    if (docPtr == nullptr) {
        ANS_LOGE("xmlReadFile return nullptr!");
        return false;
    }

    xmlNodePtr rootPtr = xmlDocGetRootElement(docPtr);
    if (rootPtr == nullptr || rootPtr->name == nullptr ||
        xmlStrcmp(rootPtr->name, reinterpret_cast<const xmlChar *>("slotTypeConfig")) != 0) {
        ANS_LOGE("got RootElement return nullptr!");
        xmlFreeDoc(docPtr);
        return false;
    }
    for (xmlNodePtr curNodePtr = rootPtr->children; curNodePtr != nullptr; curNodePtr = curNodePtr->next) {
        std::string subName = reinterpret_cast<const char *>(curNodePtr->name);
        if (strcasecmp(subName.c_str(), "slotType") != 0) {
            return false;
        }
        xmlNodePtr subNodePtr = curNodePtr->children;
        std::string subNodeName = reinterpret_cast<const char *>(subNodePtr->children->content);
        std::string reminderFlagsName = reinterpret_cast<const char *>(subNodePtr->next->name);
        for (int i = 0; i < NotificationConstant::SLOTTYPE_MAX; i++) {
            if (strcasecmp(subNodeName.c_str(), NotificationConstant::SLOTTYPECCMNAMES[i]) == 0 &&
                strcasecmp(reminderFlagsName.c_str(), "reminderFlags") == 0) {
                uint32_t flagsDecimal = binaryToDecimal(reinterpret_cast<const char *>(subNodePtr->
                    next->children->content));
                ANS_LOGD("Ccm Got insertMap item slotType =%{public}s, slotFlags = %{public}d\n",
                    subNodeName.c_str(), flagsDecimal);
                slotFlagsMap.insert(std::make_pair(subNodeName, flagsDecimal));
            }
        }
    }
    return (slotFlagsMap.size() > 0) ? true : false;
}

bool NotificationConfigFile::getNotificationSlotFlagConfig(
    std::string &filePath, std::map<std::string, uint32_t> &slotFlagsMap)
{
    struct stat buffer;
    if (stat(filePath.c_str(), &buffer) != 0) {
        getDefaultSlotFlagsMap(slotFlagsMap);
        return true;
    } else {
        return parseNotificationConfigCcmFile(filePath, slotFlagsMap);
    }
}
} // namespace Notification
} // namespace OHOS
