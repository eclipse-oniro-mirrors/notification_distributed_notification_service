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

#include <gtest/gtest.h>

#define private public
#include "voice_extension_wrapper.h"
#undef private

#include "mock_dlfcn.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;
using namespace OHOS::Notification::Infra;
using namespace OHOS::Notification::Infra::Test;

class VoiceExtensionWrapperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        ResetMockDlfcn();
        auto& wrapper = VoiceExtensionWrapper::GetInstance();
        wrapper.CloseExtensionWrapper();
    }
    void TearDown() override
    {
        auto& wrapper = VoiceExtensionWrapper::GetInstance();
        wrapper.CloseExtensionWrapper();
        ResetMockDlfcn();
    }
};

/**
 * @tc.name: EnsureLoaded_001
 * @tc.desc: Test dlopen fails, EnsureLoaded returns early, GenerateVoiceContent returns ERR_FAIL.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, EnsureLoaded_001, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = false;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
    EXPECT_FALSE(wrapper.loaded_.load());
    EXPECT_EQ(wrapper.ExtensionHandle_, nullptr);
}

/**
 * @tc.name: EnsureLoaded_002
 * @tc.desc: Test dlsym GenerateVoiceContent fails, dlclose called.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, EnsureLoaded_002, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["GenerateVoiceContent"] = false;
    g_mockDlfcn.dlsymSuccessMap["UpdateVoiceConfig"] = true;
    g_mockDlfcn.dlsymSuccessMap["NotifyVoiceEvent"] = true;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
    EXPECT_FALSE(wrapper.loaded_.load());
    EXPECT_EQ(wrapper.ExtensionHandle_, nullptr);
    EXPECT_TRUE(g_mockDlfcn.dlcloseCalled);
}

/**
 * @tc.name: EnsureLoaded_003
 * @tc.desc: Test dlsym UpdateVoiceConfig fails, previous symbols cleared.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, EnsureLoaded_003, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["GenerateVoiceContent"] = true;
    g_mockDlfcn.dlsymSuccessMap["UpdateVoiceConfig"] = false;
    g_mockDlfcn.dlsymSuccessMap["NotifyVoiceEvent"] = true;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
    EXPECT_EQ(wrapper.generateVoiceContent_, nullptr);
    EXPECT_TRUE(g_mockDlfcn.dlcloseCalled);
}

/**
 * @tc.name: EnsureLoaded_004
 * @tc.desc: Test dlsym NotifyVoiceEvent fails, previous symbols cleared.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, EnsureLoaded_004, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["GenerateVoiceContent"] = true;
    g_mockDlfcn.dlsymSuccessMap["UpdateVoiceConfig"] = true;
    g_mockDlfcn.dlsymSuccessMap["NotifyVoiceEvent"] = false;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
    EXPECT_EQ(wrapper.generateVoiceContent_, nullptr);
    EXPECT_EQ(wrapper.updateVoiceConfig_, nullptr);
    EXPECT_TRUE(g_mockDlfcn.dlcloseCalled);
}

/**
 * @tc.name: EnsureLoaded_005
 * @tc.desc: Test full success path with empty cached config, fast path on second call.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, EnsureLoaded_005, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.generateResult = 0;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_OK);
    EXPECT_TRUE(wrapper.loaded_.load());
    EXPECT_NE(wrapper.generateVoiceContent_, nullptr);
    EXPECT_EQ(wrapper.cachedVoiceConfig_, "");

    g_mockDlfcn.dlcloseCalled = false;
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_OK);
    EXPECT_FALSE(g_mockDlfcn.dlcloseCalled);
}

/**
 * @tc.name: EnsureLoaded_006
 * @tc.desc: Test cached config applied on successful load.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, EnsureLoaded_006, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = false;
    std::string config = "cached_config";
    EXPECT_EQ(wrapper.UpdateVoiceConfig(config), VoiceExtensionWrapper::ErrorCode::ERR_OK);
    EXPECT_EQ(wrapper.cachedVoiceConfig_, config);

    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.updateResult = 0;
    g_mockDlfcn.generateResult = 0;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_OK);
    EXPECT_TRUE(wrapper.loaded_.load());
    EXPECT_EQ(wrapper.cachedVoiceConfig_, "");
    EXPECT_EQ(g_mockDlfcn.lastUpdateConfig, config);
}

/**
 * @tc.name: GenerateVoiceContent_001
 * @tc.desc: Test GenerateVoiceContent returns ERR_FAIL when loaded_ true but func nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, GenerateVoiceContent_001, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    wrapper.loaded_ = true;
    wrapper.generateVoiceContent_ = nullptr;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
}

/**
 * @tc.name: GenerateVoiceContent_002
 * @tc.desc: Test GenerateVoiceContent propagates error from underlying function.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, GenerateVoiceContent_002, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.generateResult = VoiceExtensionWrapper::ErrorCode::ERR_FAIL;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.GenerateVoiceContent(request, content, externInfo),
        VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
}

/**
 * @tc.name: UpdateVoiceConfig_001
 * @tc.desc: Test UpdateVoiceConfig fast path when SO loaded.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, UpdateVoiceConfig_001, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.updateResult = 0;
    g_mockDlfcn.generateResult = 0;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    wrapper.GenerateVoiceContent(request, content, externInfo);

    std::string config = "config_v1";
    EXPECT_EQ(wrapper.UpdateVoiceConfig(config), VoiceExtensionWrapper::ErrorCode::ERR_OK);
    EXPECT_EQ(g_mockDlfcn.lastUpdateConfig, config);
    EXPECT_EQ(wrapper.cachedVoiceConfig_, "");
}

/**
 * @tc.name: UpdateVoiceConfig_002
 * @tc.desc: Test UpdateVoiceConfig propagates error from underlying function.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, UpdateVoiceConfig_002, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.generateResult = 0;
    g_mockDlfcn.updateResult = VoiceExtensionWrapper::ErrorCode::ERR_FAIL;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    wrapper.GenerateVoiceContent(request, content, externInfo);

    std::string config = "config_err";
    EXPECT_EQ(wrapper.UpdateVoiceConfig(config), VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
}

/**
 * @tc.name: UpdateVoiceConfig_003
 * @tc.desc: Test UpdateVoiceConfig caches when loaded_ true but updateVoiceConfig_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, UpdateVoiceConfig_003, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    wrapper.loaded_ = true;
    wrapper.updateVoiceConfig_ = nullptr;
    std::string config = "orphan_config";
    EXPECT_EQ(wrapper.UpdateVoiceConfig(config), VoiceExtensionWrapper::ErrorCode::ERR_OK);
    EXPECT_EQ(wrapper.cachedVoiceConfig_, config);
}

/**
 * @tc.name: NotifyVoiceEvent_001
 * @tc.desc: Test NotifyVoiceEvent skips when not loaded, returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, NotifyVoiceEvent_001, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    wrapper.loaded_ = false;
    wrapper.notifyVoiceEvent_ = nullptr;
    sptr<NotificationRequest> request = new NotificationRequest();
    EXPECT_EQ(wrapper.NotifyVoiceEvent("EVENT_REMOVED", request),
        VoiceExtensionWrapper::ErrorCode::ERR_OK);
}

/**
 * @tc.name: NotifyVoiceEvent_002
 * @tc.desc: Test NotifyVoiceEvent success with SO loaded.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, NotifyVoiceEvent_002, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.generateResult = 0;
    g_mockDlfcn.notifyResult = 0;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    wrapper.GenerateVoiceContent(request, content, externInfo);

    EXPECT_EQ(wrapper.NotifyVoiceEvent("EVENT_REMOVED", request),
        VoiceExtensionWrapper::ErrorCode::ERR_OK);
    EXPECT_EQ(g_mockDlfcn.lastNotifyEvent, "EVENT_REMOVED");
}

/**
 * @tc.name: NotifyVoiceEvent_003
 * @tc.desc: Test NotifyVoiceEvent propagates error from underlying function.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, NotifyVoiceEvent_003, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.generateResult = 0;
    g_mockDlfcn.notifyResult = VoiceExtensionWrapper::ErrorCode::ERR_FAIL;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    wrapper.GenerateVoiceContent(request, content, externInfo);

    EXPECT_EQ(wrapper.NotifyVoiceEvent("EVENT_ERROR", request),
        VoiceExtensionWrapper::ErrorCode::ERR_FAIL);
}

/**
 * @tc.name: CloseExtensionWrapper_001
 * @tc.desc: Test CloseExtensionWrapper with valid handle calls dlclose, and with null handle clears state.
 * @tc.type: FUNC
 */
HWTEST_F(VoiceExtensionWrapperTest, CloseExtensionWrapper_001, Function | SmallTest | Level1)
{
    auto& wrapper = VoiceExtensionWrapper::GetInstance();
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.generateResult = 0;
    g_mockDlfcn.dlcloseCalled = false;
    std::string content;
    std::string externInfo;
    sptr<NotificationRequest> request = new NotificationRequest();
    wrapper.GenerateVoiceContent(request, content, externInfo);
    EXPECT_NE(wrapper.ExtensionHandle_, nullptr);

    wrapper.CloseExtensionWrapper();
    EXPECT_TRUE(g_mockDlfcn.dlcloseCalled);
    EXPECT_EQ(wrapper.ExtensionHandle_, nullptr);
    EXPECT_EQ(wrapper.generateVoiceContent_, nullptr);
    EXPECT_FALSE(wrapper.loaded_.load());

    wrapper.loaded_ = true;
    wrapper.cachedVoiceConfig_ = "cached";
    wrapper.ExtensionHandle_ = nullptr;
    wrapper.CloseExtensionWrapper();
    EXPECT_EQ(wrapper.cachedVoiceConfig_, "");
    EXPECT_FALSE(wrapper.loaded_.load());
}