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
#include "mock_ability_manager_client.h"

namespace {
constexpr const char* DEFAULT_TOP_ABILITY_BUNDLE = "topName";
std::string g_topAbilityBundleName = DEFAULT_TOP_ABILITY_BUNDLE;
std::string g_topAbilityFirstBundleName = "";
bool g_topAbilitySequenceEnabled = false;
int32_t g_lastTopAbilityUserId = -1;
bool g_lastTopAbilityNeedLocalDeviceId = true;
int32_t g_topAbilityCallCount = 0;
}

namespace OHOS {
namespace AAFwk {

void MockSetTopAbilityBundleName(const std::string &bundleName)
{
    g_topAbilityBundleName = bundleName;
    g_topAbilitySequenceEnabled = false;
}

void MockSetTopAbilityBundleNameSequence(const std::string &firstBundle, const std::string &restBundle)
{
    g_topAbilityFirstBundleName = firstBundle;
    g_topAbilityBundleName = restBundle;
    g_topAbilitySequenceEnabled = true;
}

void MockResetTopAbility()
{
    g_topAbilityBundleName = DEFAULT_TOP_ABILITY_BUNDLE;
    g_topAbilityFirstBundleName = "";
    g_topAbilitySequenceEnabled = false;
    g_lastTopAbilityUserId = -1;
    g_lastTopAbilityNeedLocalDeviceId = true;
    g_topAbilityCallCount = 0;
}

int32_t MockGetLastTopAbilityUserId()
{
    return g_lastTopAbilityUserId;
}

bool MockGetLastTopAbilityNeedLocalDeviceId()
{
    return g_lastTopAbilityNeedLocalDeviceId;
}

int32_t MockGetTopAbilityCallCount()
{
    return g_topAbilityCallCount;
}

std::shared_ptr<MockAbilityManagerClient> MockAbilityManagerClient::mockinstance_ = nullptr;
std::shared_ptr<MockAbilityManagerClient> MockAbilityManagerClient::GetInstance()
{
    if (mockinstance_ == nullptr) {
        mockinstance_ = std::make_shared<MockAbilityManagerClient>();
    }
    return mockinstance_;
}

std::shared_ptr<AbilityManagerClient> AbilityManagerClient::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = MockAbilityManagerClient::GetInstance();
    }
    return instance_;
}

AppExecFwk::ElementName AbilityManagerClient::GetTopAbility(bool isNeedLocalDeviceId, int32_t userId)
{
    g_lastTopAbilityUserId = userId;
    g_lastTopAbilityNeedLocalDeviceId = isNeedLocalDeviceId;
    g_topAbilityCallCount++;
    AppExecFwk::ElementName elementName = {};
    if (g_topAbilitySequenceEnabled && g_topAbilityCallCount == 1) {
        elementName.SetBundleName(g_topAbilityFirstBundleName);
        return elementName;
    }
    elementName.SetBundleName(g_topAbilityBundleName);
    return elementName;
}
}  // namespace AAFwk
}  // namespace OHOS