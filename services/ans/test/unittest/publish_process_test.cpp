/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#define private public
#define protected public
#include "common_notification_publish_process.h"
#include "ans_inner_errors.h"
#include "live_publish_process.h"
#include "accesstoken_kit.h"
#include "notification_content.h"
#include "notification_constant.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace Notification {

extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemAppByFullTokenID(bool isSystemApp);
extern void MockDlpType(DlpType mockRet);
extern void MockIsSystemApp(bool isSystemApp);

class PublishProcessTest : public testing::Test {
public:
    PublishProcessTest()
    {}
    ~PublishProcessTest()
    {}
    static void SetUpTestCas(void) {};
    static void TearDownTestCase(void) {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Test CommonPublishCheck
 * @tc.desc: Test CommonPublishCheck
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, BaseCommonPublishCheck_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemAppByFullTokenID(false);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetReceiverUserId(100);

    CommonNotificationPublishProcess process;
    auto res = process.CommonPublishCheck(request);
    ASSERT_EQ(res, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: Test CommonPublishCheck
 * @tc.desc: Test CommonPublishCheck
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, BaseCommonPublishCheck_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemAppByFullTokenID(true);
    MockIsVerfyPermisson(false);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetReceiverUserId(100);

    CommonNotificationPublishProcess process;
    auto res = process.CommonPublishCheck(request);
    ASSERT_EQ(res, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: Test CommonPublishProcess
 * @tc.desc: Test CommonPublishProcess
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, BaseCommonPublishProcess_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockDlpType(DlpType::DLP_READ);
    sptr<NotificationRequest> request(new NotificationRequest(1));

    CommonNotificationPublishProcess process;
    auto res = process.CommonPublishProcess(request);
    ASSERT_EQ(res, ERR_ANS_DLP_HAP);
}

/**
 * @tc.name: Test PublishNotificationByApp
 * @tc.desc: Test PublishNotificationByApp
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, PublishNotificationByApp_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemAppByFullTokenID(false);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetReceiverUserId(100);

    CommonNotificationPublishProcess progress;
    auto res = progress.PublishNotificationByApp(request);
    ASSERT_EQ(res, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: Test PublishNotificationByApp
 * @tc.desc: Test PublishNotificationByApp
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, PublishNotificationByApp_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetInProgress(true);
    
    CommonNotificationPublishProcess progress;
    auto res = progress.PublishNotificationByApp(request);
    ASSERT_EQ(request->IsInProgress(), false);
}

/**
 * @tc.name: Test PublishNotificationByApp
 * @tc.desc: Test PublishNotificationByApp
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, PublishNotificationByApp_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockDlpType(DlpType::DLP_READ);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    
    CommonNotificationPublishProcess progress;
    auto res = progress.PublishNotificationByApp(request);
    ASSERT_EQ(res, ERR_ANS_DLP_HAP);
}

/**
 * @tc.name: Test LivePublishPreWork
 * @tc.desc: Test LivePublishPreWork
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, LivePublishPreWork_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetRemoveAllowed(false);
    
    LivePublishProcess progress;
    auto res = progress.PublishPreWork(request, true);
    ASSERT_EQ(request->IsRemoveAllowed(), true);
    ASSERT_EQ(res, ERR_OK);
}

/**
 * @tc.name: Test LivePublishPreWork
 * @tc.desc: Test LivePublishPreWork
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, LivePublishPreWork_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    
    LivePublishProcess progress;
    auto res = progress.PublishPreWork(request, true);
    ASSERT_EQ(res, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Test LivePublishNotificationByApp_00001
 * @tc.desc: Test LivePublishNotificationByApp_00001
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, LivePublishNotificationByApp_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    std::shared_ptr<NotificationLocalLiveViewContent> liveViewContent =
        std::make_shared<NotificationLocalLiveViewContent>();
    std::shared_ptr<NotificationContent> content =
        std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetReceiverUserId(100);
   
    LivePublishProcess progress;
    auto res = progress.PublishPreWork(request, false);
    ASSERT_EQ(res, ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: Test LivePublishNotificationByApp_00002
 * @tc.desc: Test LivePublishNotificationByApp_00002
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, LivePublishNotificationByApp_00002, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetInProgress(true);
    
    LivePublishProcess progress;
    auto res = progress.PublishNotificationByApp(request);
    ASSERT_EQ(request->IsInProgress(), false);
}

/**
 * @tc.name: Test LivePublishNotificationByApp_00002
 * @tc.desc: Test LivePublishNotificationByApp_00002
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, LivePublishNotificationByApp_00003, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockDlpType(DlpType::DLP_READ);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetInProgress(true);
    
    LivePublishProcess progress;
    auto res = progress.PublishNotificationByApp(request);
    ASSERT_EQ(res, ERR_ANS_DLP_HAP);
}


/**
 * @tc.name: Test LiveCheckLocalLiveViewSubscribed_00001
 * @tc.desc: Test LiveCheckLocalLiveViewSubscribed_00001
 * @tc.type: FUNC
 */
HWTEST_F(PublishProcessTest, LiveCheckLocalLiveViewSubscribed_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);

    std::shared_ptr<NotificationLiveViewContent> liveViewContent =
        std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetIsOnlyLocalUpdate(true);
    std::shared_ptr<NotificationContent> content =
        std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    
    LivePublishProcess progress;
    auto res = progress.CheckLocalLiveViewSubscribed(request, true, 100);
    ASSERT_FALSE(res);
}
}   //namespace Notification
}   //namespace OHOS