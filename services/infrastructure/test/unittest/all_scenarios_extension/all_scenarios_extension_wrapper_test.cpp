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
#include "all_scenarios_extension_wrapper.h"
#undef private

#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "mock_dlfcn.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;
using namespace OHOS::Notification::Infra;
using namespace OHOS::Notification::Infra::Test;

class AllScenariosExtensionWrapperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        ResetMockDlfcn();
        auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
        wrapper.CloseExtensionWrapper();
    }
    void TearDown() override
    {
        auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
        wrapper.CloseExtensionWrapper();
        ResetMockDlfcn();
    }
};

/**
 * @tc.name: CheckLiveViewRights_001
 * @tc.desc: Symbol available + rights check passes (returns ERR_OK).
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, CheckLiveViewRights_001, Function | SmallTest | Level1)
{
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["CheckLiveViewRights"] = true;
    g_mockDlfcn.checkLiveViewRightsResult = ERR_OK;

    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    wrapper.InitExtensionWrapper();

    sptr<NotificationRequest> request = new NotificationRequest();
    ErrCode result = wrapper.CheckLiveViewRights(request);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckLiveViewRights_002
 * @tc.desc: Symbol not available (dlsym returns nullptr, simulating old version .so).
 *           CheckLiveViewRights should return ERR_OK (skip check).
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, CheckLiveViewRights_002, Function | SmallTest | Level1)
{
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["CheckLiveViewRights"] = false;

    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    wrapper.InitExtensionWrapper();

    sptr<NotificationRequest> request = new NotificationRequest();
    ErrCode result = wrapper.CheckLiveViewRights(request);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckLiveViewRights_003
 * @tc.desc: Symbol available + rights check fails (returns non-ERR_OK).
 *           CheckLiveViewRights should return the original error code.
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, CheckLiveViewRights_003, Function | SmallTest | Level1)
{
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["CheckLiveViewRights"] = true;
    g_mockDlfcn.checkLiveViewRightsResult = ERR_ANS_INNER_CUSTOM_EXTENSION_RIGHTS_CHECK_FAILED;

    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    wrapper.InitExtensionWrapper();

    sptr<NotificationRequest> request = new NotificationRequest();
    ErrCode result = wrapper.CheckLiveViewRights(request);
    if (wrapper.ExtensionHandle_ == nullptr || wrapper.checkLiveViewRights_ == nullptr) {
        GTEST_SKIP() << "libliveview.z.so not exist";
    }
    EXPECT_EQ(result, ERR_ANS_INNER_CUSTOM_EXTENSION_RIGHTS_CHECK_FAILED);
}

/**
 * @tc.name: CheckLiveViewRights_004
 * @tc.desc: dlopen fails (.so not found). CheckLiveViewRights should return ERR_OK (skip check).
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, CheckLiveViewRights_004, Function | SmallTest | Level1)
{
    g_mockDlfcn.dlopenSuccess = false;

    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    wrapper.InitExtensionWrapper();

    sptr<NotificationRequest> request = new NotificationRequest();
    ErrCode result = wrapper.CheckLiveViewRights(request);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ErrorToExternal_CustomExtension_001
 * @tc.desc: Verify ErrorToExternal mapping for the two custom extension error codes.
 *           EXISTS_CHECK maps to ERROR_LIVE_VIEW_EXTENSION_NOT_FOUND (1600029);
 *           RIGHTS_CHECK maps to ERROR_NO_RIGHT (1600014).
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, ErrorToExternal_CustomExtension_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_CUSTOM_EXTENSION_EXISTS_CHECK_FAILED),
        ERROR_LIVE_VIEW_EXTENSION_NOT_FOUND);
    EXPECT_EQ(InnerErrorToExternal(ERR_ANS_INNER_CUSTOM_EXTENSION_RIGHTS_CHECK_FAILED), ERROR_NO_RIGHT);
}

/**
 * @tc.name: OnCleanup_001
 * @tc.desc: Symbol available + extension returns ERR_OK. OnCleanup should
 *           return ERR_OK and the extension entry should be invoked once.
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, OnCleanup_001, Function | SmallTest | Level1)
{
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["OnCleanup"] = true;
    g_mockDlfcn.onCleanupResult = ERR_OK;

    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    wrapper.InitExtensionWrapper();

    ErrCode result = wrapper.OnCleanup();
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(g_mockDlfcn.onCleanupCalled, 1);
}

/**
 * @tc.name: OnCleanup_002
 * @tc.desc: Symbol not available (dlsym returns nullptr, simulating old version .so).
 *           OnCleanup should return ERR_OK (skip notify) without calling the entry.
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, OnCleanup_002, Function | SmallTest | Level1)
{
    g_mockDlfcn.dlopenSuccess = true;
    g_mockDlfcn.dlsymSuccessMap["OnCleanup"] = false;

    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    wrapper.InitExtensionWrapper();

    ErrCode result = wrapper.OnCleanup();
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(g_mockDlfcn.onCleanupCalled, 0);
}

/**
 * @tc.name: OnCleanup_003
 * @tc.desc: dlopen fails (.so not found). OnCleanup should return ERR_OK (skip notify).
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, OnCleanup_003, Function | SmallTest | Level1)
{
    g_mockDlfcn.dlopenSuccess = false;

    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    wrapper.InitExtensionWrapper();

    ErrCode result = wrapper.OnCleanup();
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(g_mockDlfcn.onCleanupCalled, 0);
}

/**
 * @tc.name: CloseExtensionWrapper_001
 * @tc.desc: Test CloseExtensionWrapper resets onNotifyDelayedNotification_ and
 *           onNotifyClearNotification_ together with other cached symbols.
 * @tc.type: FUNC
 */
HWTEST_F(AllScenariosExtensionWrapperTest, CloseExtensionWrapper_001, Function | SmallTest | Level1)
{
    auto& wrapper = AllScenariosExtensionWrapper::GetInstance();
    if (wrapper.ExtensionHandle_ == nullptr) {
        wrapper.ExtensionHandle_ = reinterpret_cast<void *>(0x1);
    }
    wrapper.onNotifyDelayedNotification_ =
        +[](const sptr<NotificationRequest> &request) -> ErrCode { return ERR_OK; };
    wrapper.onNotifyClearNotification_ =
        +[](const std::vector<std::string> &triggerKeys) -> ErrCode { return ERR_OK; };
    ASSERT_NE(wrapper.ExtensionHandle_, nullptr);
    ASSERT_NE(wrapper.onNotifyDelayedNotification_, nullptr);
    ASSERT_NE(wrapper.onNotifyClearNotification_, nullptr);

    wrapper.CloseExtensionWrapper();

    EXPECT_EQ(wrapper.ExtensionHandle_, nullptr);
    EXPECT_EQ(wrapper.onNotifyDelayedNotification_, nullptr);
    EXPECT_EQ(wrapper.onNotifyClearNotification_, nullptr);
}
