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
#include "gmock/gmock.h"

#define private public
#define protected public
#include "clone/clone_start_event_subscriber.h"
#include "system_event_observer.h"
#include "notification_clone_manager.h"
#undef private
#undef protected

#include "common_event_support.h"
#include "want.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace Notification;

namespace {
const std::string TEST_DATACLONE_BUNDLE_NAME = "com.example.dataclone";
}  // anonymous namespace

class CloneStartEventSubscriberTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(CloneStartEventSubscriber::CLONE_EVENT_START);
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        subscribeInfo.SetPublisherBundleName(TEST_DATACLONE_BUNDLE_NAME);
        subscriber_ = std::make_shared<CloneStartEventSubscriber>(subscribeInfo);
    }

    void TearDown() override
    {
        subscriber_ = nullptr;
    }

    std::shared_ptr<CloneStartEventSubscriber> subscriber_;
};

/**
 * @tc.name: GetSubscribeInfo_00100
 * @tc.desc: Verify the subscriber configuration: only usual.event.clone.startTransfer event
 * @tc.type: FUNC
 * @tc.require: clone-start-transfer-event-validation
 */
HWTEST_F(CloneStartEventSubscriberTest, GetSubscribeInfo_00100, Function | SmallTest | Level1)
{
    ASSERT_NE(subscriber_, nullptr);

    // Verify the matching skills contain the clone start event
    std::vector<std::string> events = subscriber_->GetSubscribeInfo().GetMatchingSkills().GetEvents();
    ASSERT_EQ(events.size(), 1);
    EXPECT_EQ(events[0], CloneStartEventSubscriber::CLONE_EVENT_START);

    // Verify the publisher bundle name filter
    EXPECT_EQ(subscriber_->GetSubscribeInfo().GetPublisherBundleName(),
        TEST_DATACLONE_BUNDLE_NAME);
}

/**
 * @tc.name: OnReceiveEvent_00200
 * @tc.desc: Verify OnReceiveEvent calls NotificationCloneManager::GetInstance().OnRestoreEnd()
 *           without crash
 * @tc.type: FUNC
 * @tc.require: clone-start-transfer-event-validation
 */
HWTEST_F(CloneStartEventSubscriberTest, OnReceiveEvent_00200, Function | SmallTest | Level1)
{
    ASSERT_NE(subscriber_, nullptr);

    EventFwk::Want want;
    want.SetAction(CloneStartEventSubscriber::CLONE_EVENT_START);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    // Should not crash - just call the method directly
    subscriber_->OnReceiveEvent(data);
    SUCCEED() << "OnReceiveEvent completed without crash";
}

/**
 * @tc.name: NoCloneEventInOriginalSubscriber_00300
 * @tc.desc: Verify SystemEventObserver no longer subscribes to CLONE_EVENT_START
 *           in its matching skills and no longer handles it in OnReceiveEvent
 * @tc.type: FUNC
 * @tc.require: clone-start-transfer-event-validation
 */
HWTEST_F(CloneStartEventSubscriberTest, NoCloneEventInOriginalSubscriber_00300, Function | SmallTest | Level1)
{
    // Create a SystemEventObserver with empty callbacks
    ISystemEvent callbacks;
    SystemEventObserver observer(callbacks);

    // The subscriber_ member should not have CLONE_EVENT_START in its matching skills
    ASSERT_NE(observer.subscriber_, nullptr);
    std::vector<std::string> events = observer.subscriber_->GetSubscribeInfo().GetMatchingSkills().GetEvents();

    for (const auto &event : events) {
        EXPECT_NE(event, CloneStartEventSubscriber::CLONE_EVENT_START)
            << "SystemEventObserver should not subscribe to CLONE_EVENT_START";
    }
}
