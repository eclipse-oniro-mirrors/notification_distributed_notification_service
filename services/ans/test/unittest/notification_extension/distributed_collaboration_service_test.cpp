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

#include "ans_inner_errors.h"
#include "distributed_collaboration_service.h"

namespace OHOS {
namespace Notification {

using namespace testing::ext;

class DistributedCollaborationServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void DistributedCollaborationServiceTest::SetUpTestCase()
{
}

void DistributedCollaborationServiceTest::TearDownTestCase()
{
}

/**
 * @tc.name: Device sync switch check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedCollaborationServiceTest, CollaborativeService_00001, Function | SmallTest | Level1)
{
    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(nullptr);
    ASSERT_EQ(DistributedCollaborationService::GetInstance().collaborativeDeleteMap_.empty(), true);

    sptr<Notification> notification1 = new (std::nothrow) Notification(nullptr);
    notification1->SetKey("ans_distributed_1");
    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(notification1);
    ASSERT_EQ(DistributedCollaborationService::GetInstance().collaborativeDeleteMap_.empty(), true);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    sptr<Notification> notification2 = new (std::nothrow) Notification(request);
    notification2->SetKey("ans_distributed_2");
    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(notification2);
    ASSERT_EQ(DistributedCollaborationService::GetInstance().collaborativeDeleteMap_.empty(), true);

    request->SetDistributedCollaborate(true);
    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(notification2);
    ASSERT_EQ(DistributedCollaborationService::GetInstance().collaborativeDeleteMap_.empty(), true);

    auto liveviewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveviewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(notification2);
    ASSERT_EQ(DistributedCollaborationService::GetInstance().collaborativeDeleteMap_.empty(), false);
}

/**
 * @tc.name: Device sync switch check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedCollaborationServiceTest, CollaborativeService_00002, Function | SmallTest | Level1)
{
    auto result = DistributedCollaborationService::GetInstance().CheckCollaborativePublish(nullptr);
    ASSERT_EQ(result, true);

    sptr<Notification> notification1 = new (std::nothrow) Notification(nullptr);
    notification1->SetKey("ans_distributed_1");
    result = DistributedCollaborationService::GetInstance().CheckCollaborativePublish(notification1);
    ASSERT_EQ(result, true);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetNotificationId(1);
    sptr<Notification> notification2 = new (std::nothrow) Notification(request);
    notification2->SetKey("ans_distributed_2");
    result = DistributedCollaborationService::GetInstance().CheckCollaborativePublish(notification2);
    ASSERT_EQ(result, true);

    request->SetDistributedCollaborate(true);
    result = DistributedCollaborationService::GetInstance().CheckCollaborativePublish(notification2);
    ASSERT_EQ(result, true);

    auto liveviewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveviewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    result = DistributedCollaborationService::GetInstance().CheckCollaborativePublish(notification2);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: Collaborative Service
 * @tc.desc: Test update after delete
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedCollaborationServiceTest, CollaborativeService_00003, Function | SmallTest | Level1)
{
    DistributedCollaborationService::GetInstance().collaborativeDeleteMap_.clear();

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto liveviewContent = std::make_shared<NotificationLiveViewContent>();
    liveviewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto content = std::make_shared<NotificationContent>(liveviewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetDistributedCollaborate(true);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    notification->SetKey("ans_distributed_0003");
    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(notification);

    auto result = DistributedCollaborationService::GetInstance().CheckCollaborativePublish(notification);
    ASSERT_EQ(result, true);

    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(notification);
    liveviewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    result = DistributedCollaborationService::GetInstance().CheckCollaborativePublish(notification);
    ASSERT_EQ(result, false);
}
}
}
