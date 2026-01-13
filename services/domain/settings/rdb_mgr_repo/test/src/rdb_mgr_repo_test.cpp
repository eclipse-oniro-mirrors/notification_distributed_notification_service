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

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "gtest/gtest.h"

#include "ans_rdb_mgr_builder.h"
#include "aes_gcm_helper.h"
#include "event_report.h"
#include "notification_rdb_mgr.h"
#include "notification_content.h"
#include "nlohmann/json.hpp"
#include "notification_analytics_util.h"
#include "rdb_hooks.h"

using namespace testing::ext;

namespace {
std::atomic<int32_t> g_modifyEventReportCount {0};
OHOS::Notification::HaMetaMessage g_lastModifyEventMessage;

void ResetCapturedState()
{
    g_modifyEventReportCount.store(0);
    g_lastModifyEventMessage = OHOS::Notification::HaMetaMessage {};
}
} // namespace

namespace OHOS::Notification {
ErrCode AesGcmHelper::Encrypt(const std::string &plainText, std::string &cipherText)
{
    cipherText = plainText;
    return ERR_OK;
}

ErrCode AesGcmHelper::Decrypt(std::string &plainText, const std::string &cipherText)
{
    plainText = cipherText;
    return ERR_OK;
}

HaMetaMessage::HaMetaMessage(uint32_t sceneId, uint32_t branchId)
{
    sceneId_ = sceneId;
    branchId_ = branchId;
}

HaMetaMessage& HaMetaMessage::ErrorCode(uint32_t errorCode)
{
    errorCode_ = errorCode;
    return *this;
}

HaMetaMessage& HaMetaMessage::Message(const std::string& message, bool /*print*/)
{
    message_ = message;
    return *this;
}

std::string HaMetaMessage::GetMessage() const
{
    return message_;
}

void NotificationAnalyticsUtil::ReportModifyEvent(const HaMetaMessage& message, bool /*unFlowControl*/)
{
    g_modifyEventReportCount.fetch_add(1);
    g_lastModifyEventMessage = message;
}

} // namespace OHOS::Notification

namespace OHOS::Notification::Infra {

NotificationRdbMgr::NotificationRdbMgr(NotificationRdbConfig&, const NtfRdbHook &,
    const std::set<RdbEventHandlerType> &) {}

} // namespace OHOS::Notification::Infra

namespace OHOS::Notification::Domain {

class RdbMgrRepoTest : public ::testing::Test {
public:
    void SetUp() override
    {
        ResetCapturedState();
    }

    void TearDown() override {}
};

/**
 * @tc.name: OnRdbUpgradeLiveviewMigrate_100
 * @tc.desc: Verify live view migration when json object has wrong action buttons.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMgrRepoTest, OnRdbUpgradeLiveviewMigrate_100, Function | SmallTest | Level1)
{
    std::string newValue;
    nlohmann::json nullObject;
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(nullObject.dump(), newValue));

    nlohmann::json arrayObject = nlohmann::json::array({
        nlohmann::json{{"wantAgent", "want_agent_value"}},
        nlohmann::json{{"buttonId", 1}}
    });
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(arrayObject.dump(), newValue));

    nlohmann::json emptyActionButtons = {
        {"actionButtons", nlohmann::json::array()}
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(emptyActionButtons.dump(), newValue));

    nlohmann::json actionButtonsWithWrongType = {
        {"actionButtons", nlohmann::json{{"foo", "bar"}}}
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(actionButtonsWithWrongType.dump(), newValue));
}

/**
 * @tc.name: OnRdbUpgradeLiveviewMigrate_200
 * @tc.desc: Verify live view migration when json object has wrong content.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMgrRepoTest, OnRdbUpgradeLiveviewMigrate_200, Function | SmallTest | Level1)
{
    std::string newValue;
    const int32_t liveViewType = static_cast<int32_t>(OHOS::Notification::NotificationContent::Type::LIVE_VIEW);
    nlohmann::json objectWithoutContent = {
        {"actionButtons", nlohmann::json::array({
            nlohmann::json{{"wantAgent", "want_agent_value"}},
            nlohmann::json{{"buttonId", 1}}
        })},
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(objectWithoutContent.dump(), newValue));

    nlohmann::json objectWithContentNull = {
        {"actionButtons", nlohmann::json::array({
            nlohmann::json{{"wantAgent", "want_agent_value"}},
            nlohmann::json{{"buttonId", 1}}
        })},
        {"content", nlohmann::json{}}
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(objectWithContentNull.dump(), newValue));

    nlohmann::json objectWithoutContentType = {
        {"actionButtons", nlohmann::json::array({
            nlohmann::json{{"wantAgent", "want_agent_value"}},
            nlohmann::json{{"buttonId", 1}}
        })},
        {"content", nlohmann::json{
            {"content", nlohmann::json{{"foo", "bar"}}}
        }}
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(objectWithoutContentType.dump(), newValue));

    nlohmann::json objectWithWrongContentType = {
        {"actionButtons", nlohmann::json::array({
            nlohmann::json{{"wantAgent", "want_agent_value"}},
            nlohmann::json{{"buttonId", 1}}
        })},
        {"content", nlohmann::json{
            {"contentType", "liveViewType"},
            {"content", nlohmann::json{{"foo", "bar"}}}
        }}
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(objectWithWrongContentType.dump(), newValue));

    nlohmann::json objectWithWrongContent = {
        {"actionButtons", nlohmann::json::array({
            nlohmann::json{{"wantAgent", "want_agent_value"}},
            nlohmann::json{{"buttonId", 1}}
        })},
        {"content", nlohmann::json{
            {"contentType", "liveViewType"},
        }}
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(objectWithWrongContent.dump(), newValue));

    nlohmann::json objectWithNullContent = {
        {"actionButtons", nlohmann::json::array({
            nlohmann::json{{"wantAgent", "want_agent_value"}},
            nlohmann::json{{"buttonId", 1}}
        })},
        {"content", nlohmann::json{
            {"contentType", liveViewType},
            {"content", nlohmann::json{}}
        }}
    };
    EXPECT_FALSE(OnRdbUpgradeLiveviewMigrate(objectWithNullContent.dump(), newValue));
}

/**
 * @tc.name: OnRdbUpgradeLiveviewMigrate_300
 * @tc.desc: Verify live view migration when json object has wrong type.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMgrRepoTest, OnRdbUpgradeLiveviewMigrate_300, Function | SmallTest | Level1)
{
    std::string newValue;
    const int32_t liveViewType = static_cast<int32_t>(OHOS::Notification::NotificationContent::Type::LIVE_VIEW);

    nlohmann::json input = {
        {"actionButtons", nlohmann::json::array({
            nlohmann::json{{"wantAgent", "want_agent_value"}},
            nlohmann::json{{"buttonId", 1}}
        })},
        {"content", nlohmann::json{
            {"contentType", liveViewType},
            {"content", nlohmann::json{{"foo", "bar"}}}
        }}
    };

    EXPECT_TRUE(OnRdbUpgradeLiveviewMigrate(input.dump(), newValue));

    nlohmann::json output = nlohmann::json::parse(newValue);
    ASSERT_TRUE(output.contains("actionButtons"));
    ASSERT_TRUE(output["actionButtons"].is_array());
    EXPECT_EQ(output["actionButtons"].size(), 1);
    EXPECT_EQ(output["actionButtons"][0]["buttonId"].get<int32_t>(), 1);

    ASSERT_TRUE(output.contains("content"));
    ASSERT_TRUE(output["content"].contains("content"));
    ASSERT_TRUE(output["content"]["content"].contains("extensionWantAgent"));
    EXPECT_EQ(output["content"]["content"]["extensionWantAgent"].get<std::string>(), "want_agent_value");
}

/**
 * @tc.name: OnRdbOperationFailReport_100
 * @tc.desc: Verify operation failure hook reports modify event with expected meta info.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMgrRepoTest, OnRdbOperationFailReport_100, Function | SmallTest | Level1)
{
    OnRdbOperationFailReport(1, 2, 12345, "rdb failed");

    EXPECT_EQ(g_modifyEventReportCount.load(), 1);
    EXPECT_EQ(g_lastModifyEventMessage.sceneId_, 1u);
    EXPECT_EQ(g_lastModifyEventMessage.branchId_, 2u);
    EXPECT_EQ(g_lastModifyEventMessage.errorCode_, 12345u);
    EXPECT_EQ(g_lastModifyEventMessage.GetMessage(), "rdb failed");
}

/**
 * @tc.name: GetAnsNotificationRdbMgrInstance_100
 * @tc.desc: Verify GetAnsNotificationRdbMgrInstance returns stable singleton instance.
 * @tc.type: FUNC
 */
HWTEST_F(RdbMgrRepoTest, GetAnsNotificationRdbMgrInstance_100, Function | SmallTest | Level1)
{
    auto inst1 = GetAnsNotificationRdbMgrInstance();
    auto inst2 = GetAnsNotificationRdbMgrInstance();

    ASSERT_NE(inst1, nullptr);
    ASSERT_NE(inst2, nullptr);
    EXPECT_EQ(inst1.get(), inst2.get());
}

} // namespace OHOS::Notification::Domain