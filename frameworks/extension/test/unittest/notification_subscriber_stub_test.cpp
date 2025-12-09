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

#include <gtest/gtest.h>
#define private public
#include "notification_extension_content.h"
#include "notification_info.h"
#include "notification_request.h"
#include "notification_subscriber_extension.h"
#include "notification_subscriber_stub_impl.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSubscriberStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: OnReceiveMessage_0100
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0100, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(request, retResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnReceiveMessage_0200
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0200, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(nullptr, retResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnReceiveMessage_0300
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0300, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    std::weak_ptr<NotificationSubscriberExtension> extension = subscriberExtension;
    subscriberExtension.reset();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(request, retResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnReceiveMessage_0400
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0400, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(request, retResult);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OnCancelMessages_0100
 * @tc.desc: OnCancelMessages.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnCancelMessages_0100, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    std::weak_ptr<NotificationSubscriberExtension> extension = subscriberExtension;
    subscriberExtension.reset();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    std::vector<std::string> hashCode = {"testHash1", "testHash2"};
    int32_t retResult = 0;

    ErrCode result = stub.OnCancelMessages(hashCode, retResult);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnCancelMessages_0200
 * @tc.desc: OnCancelMessages.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnCancelMessages_0200, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    std::vector<std::string> hashCode = {"testHash1", "testHash2"};
    int32_t retResult = 0;

    ErrCode result = stub.OnCancelMessages(hashCode, retResult);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ConvertNotificationRequest_0100
 * @tc.desc: ConvertNotificationRequest.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, ConvertNotificationRequest_0100, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);

    auto notificationInfo = stub.ConvertNotificationRequest(request);
    EXPECT_EQ(notificationInfo, nullptr);
}

/**
 * @tc.name: ConvertNotificationRequest_0200
 * @tc.desc: ConvertNotificationRequest.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, ConvertNotificationRequest_0200, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto content = std::make_shared<NotificationContent>(std::shared_ptr<NotificationNormalContent>(nullptr));
    request->SetContent(content);

    auto notificationInfo = stub.ConvertNotificationRequest(request);
    EXPECT_EQ(notificationInfo, nullptr);
}

/**
 * @tc.name: ConvertNotificationRequest_0300
 * @tc.desc: ConvertNotificationRequest.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, ConvertNotificationRequest_0300, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("TestText");
    normalContent->SetTitle("TestTitle");
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    request->SetCreatorBundleName("CreatorBundleName");
    request->SetOwnerBundleName("OwnerBundleName");
    request->SetAppName("TestAppName");
    request->SetDeliveryTime(1);
    request->SetGroupName("TestGroupName");
    request->SetAppIndex(10);

    auto notificationInfo = stub.ConvertNotificationRequest(request);
    EXPECT_NE(notificationInfo, nullptr);
    EXPECT_NE(notificationInfo->GetNotificationExtensionContent(), nullptr);
    EXPECT_EQ(notificationInfo->GetNotificationExtensionContent()->GetText(), "TestText");
    EXPECT_EQ(notificationInfo->GetNotificationExtensionContent()->GetTitle(), "TestTitle");
    EXPECT_NE(notificationInfo->GetHashCode(), "");
    EXPECT_EQ(notificationInfo->GetNotificationSlotType(), NotificationConstant::SlotType::CONTENT_INFORMATION);
    EXPECT_EQ(notificationInfo->GetBundleName(), "OwnerBundleName");
    EXPECT_EQ(notificationInfo->GetAppName(), "TestAppName");
    EXPECT_EQ(notificationInfo->GetDeliveryTime(), 1);
    EXPECT_EQ(notificationInfo->GetGroupName(), "TestGroupName");
    EXPECT_EQ(notificationInfo->GetAppIndex(), 10);
}

/**
 * @tc.name: Create_0100
 * @tc.desc: Create
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, Create_0100, Function | SmallTest | Level1)
{
    std::unique_ptr<AbilityRuntime::Runtime> runtime;
    auto ext = NotificationSubscriberExtension::Create(runtime);
    EXPECT_NE(ext, nullptr);
    EXPECT_TRUE(dynamic_cast<NotificationSubscriberExtension *>(ext) != nullptr);
    delete ext;
}

/**
 * @tc.name: Init_0100
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, Init_0100, Function | SmallTest | Level1)
{
    NotificationSubscriberExtension ext;
    std::shared_ptr<AppExecFwk::AbilityLocalRecord> record;
    std::shared_ptr<AppExecFwk::OHOSApplication> application;
    std::shared_ptr<AppExecFwk::AbilityHandler> handler;
    sptr<IRemoteObject> token;
    ext.Init(record, application, handler, token);
    EXPECT_NE(ext.GetContext(), nullptr);
}

/**
 * @tc.name: CreateAndInitContext_0100
 * @tc.desc: CreateAndInitContext
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, CreateAndInitContext_0100, Function | SmallTest | Level1)
{
    NotificationSubscriberExtension ext;
    std::shared_ptr<AppExecFwk::AbilityLocalRecord> record;
    std::shared_ptr<AppExecFwk::OHOSApplication> application;
    std::shared_ptr<AppExecFwk::AbilityHandler> handler;
    sptr<IRemoteObject> token;
    auto context = ext.CreateAndInitContext(record, application, handler, token);
    EXPECT_NE(context, nullptr);
    EXPECT_TRUE(dynamic_cast<NotificationSubscriberExtensionContext *>(context.get()) != nullptr);
}

/**
 * @tc.name: NotificationInfo_Dump_0100
 * @tc.desc: Verify Dump with all fields and content.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_Dump_0100, Function | SmallTest | Level1)
{
    NotificationInfo info;
    info.SetHashCode("HashXYZ");
    info.SetNotificationSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    auto extContent = std::make_shared<NotificationExtensionContent>();
    extContent->SetTitle("TitleA");
    extContent->SetText("TextB");
    info.SetNotificationExtensionContent(extContent);
    info.SetBundleName("BundleA");
    info.SetAppName("AppA");
    info.SetDeliveryTime(123456789);
    info.SetGroupName("GroupA");

    std::string dumpStr = info.Dump();
    EXPECT_NE(dumpStr.find("HashXYZ"), std::string::npos);
    EXPECT_NE(dumpStr.find(std::to_string(static_cast<int64_t>(NotificationConstant::SlotType::CONTENT_INFORMATION))),
        std::string::npos);
    EXPECT_NE(dumpStr.find("TitleA"), std::string::npos);
    EXPECT_NE(dumpStr.find("TextB"), std::string::npos);
    EXPECT_NE(dumpStr.find("BundleA"), std::string::npos);
    EXPECT_NE(dumpStr.find("AppA"), std::string::npos);
    EXPECT_NE(dumpStr.find("123456789"), std::string::npos);
    EXPECT_NE(dumpStr.find("GroupA"), std::string::npos);
}

/**
 * @tc.name: NotificationInfo_Dump_0200
 * @tc.desc: Verify Dump when content is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_Dump_0200, Function | SmallTest | Level1)
{
    NotificationInfo info;
    info.SetHashCode("NoContentHash");
    info.SetNotificationSlotType(NotificationConstant::SlotType::CUSTOM);
    std::string dumpStr = info.Dump();
    EXPECT_NE(dumpStr.find("NoContentHash"), std::string::npos);
    EXPECT_NE(dumpStr.find("null"), std::string::npos);
    EXPECT_NE(
        dumpStr.find(std::to_string(static_cast<int64_t>(NotificationConstant::SlotType::CUSTOM))), std::string::npos);
}

/**
 * @tc.name: NotificationInfo_ToJson_0100
 * @tc.desc: Verify ToJson success with content.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_ToJson_0100, Function | SmallTest | Level1)
{
    NotificationInfo info;
    info.SetHashCode("JsonHash");
    info.SetNotificationSlotType(NotificationConstant::SlotType::SERVICE_REMINDER);
    auto extContent = std::make_shared<NotificationExtensionContent>();
    extContent->SetTitle("JsonTitle");
    extContent->SetText("JsonText");
    info.SetNotificationExtensionContent(extContent);
    info.SetBundleName("JsonBundle");
    info.SetAppName("JsonApp");
    info.SetDeliveryTime(999);
    info.SetGroupName("JsonGroup");

    nlohmann::json obj;
    bool ret = info.ToJson(obj);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(obj.is_object());
    EXPECT_EQ(obj["hashCode"].get<std::string>(), "JsonHash");
    EXPECT_EQ(obj["notificationSlotType"].get<int32_t>(),
        static_cast<int32_t>(NotificationConstant::SlotType::SERVICE_REMINDER));
    EXPECT_TRUE(obj.contains("content"));
    EXPECT_EQ(obj["content"]["title"].get<std::string>(), "JsonTitle");
    EXPECT_EQ(obj["content"]["text"].get<std::string>(), "JsonText");
    EXPECT_EQ(obj["bundleName"].get<std::string>(), "JsonBundle");
    EXPECT_EQ(obj["appName"].get<std::string>(), "JsonApp");
    EXPECT_EQ(obj["deliveryTime"].get<int64_t>(), 999);
    EXPECT_EQ(obj["groupName"].get<std::string>(), "JsonGroup");
}

/**
 * @tc.name: NotificationInfo_ToJson_0200
 * @tc.desc: Verify ToJson without content (content key absent).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_ToJson_0200, Function | SmallTest | Level1)
{
    NotificationInfo info;
    info.SetHashCode("JsonHash2");
    info.SetNotificationSlotType(NotificationConstant::SlotType::ILLEGAL_TYPE);
    nlohmann::json obj;
    bool ret = info.ToJson(obj);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(obj.is_object());
    EXPECT_EQ(obj["hashCode"].get<std::string>(), "JsonHash2");
    EXPECT_EQ(
        obj["notificationSlotType"].get<int32_t>(), static_cast<int32_t>(NotificationConstant::SlotType::ILLEGAL_TYPE));
    EXPECT_FALSE(obj.contains("content"));
}

/**
 * @tc.name: NotificationInfo_Marshalling_0100
 * @tc.desc: Verify Marshalling success and Unmarshalling restores fields.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_Marshalling_0100, Function | SmallTest | Level1)
{
    NotificationInfo info;
    info.SetHashCode("ParcelHash");
    info.SetNotificationSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    auto extContent = std::make_shared<NotificationExtensionContent>();
    extContent->SetTitle("ParcelTitle");
    extContent->SetText("ParcelText");
    info.SetNotificationExtensionContent(extContent);
    info.SetBundleName("ParcelBundle");
    info.SetAppName("ParcelApp");
    info.SetDeliveryTime(111);
    info.SetGroupName("ParcelGroup");

    Parcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    parcel.RewindRead(0);
    std::unique_ptr<NotificationInfo> back(NotificationInfo::Unmarshalling(parcel));
    EXPECT_NE(back, nullptr);
    EXPECT_EQ(back->GetHashCode(), "ParcelHash");
    EXPECT_EQ(back->GetNotificationSlotType(), NotificationConstant::SlotType::CONTENT_INFORMATION);
    EXPECT_NE(back->GetNotificationExtensionContent(), nullptr);
    EXPECT_EQ(back->GetNotificationExtensionContent()->GetTitle(), "ParcelTitle");
    EXPECT_EQ(back->GetNotificationExtensionContent()->GetText(), "ParcelText");
    EXPECT_EQ(back->GetBundleName(), "ParcelBundle");
    EXPECT_EQ(back->GetAppName(), "ParcelApp");
    EXPECT_EQ(back->GetDeliveryTime(), 111);
    EXPECT_EQ(back->GetGroupName(), "ParcelGroup");
}

/**
 * @tc.name: NotificationInfo_Unmarshalling_Fail_0100
 * @tc.desc: Verify Unmarshalling failure when content missing (ReadFromParcel returns false).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_Unmarshalling_Fail_0100, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteString("BadParcelHash"));
    EXPECT_TRUE(parcel.WriteInt32(static_cast<int32_t>(NotificationConstant::SlotType::SERVICE_REMINDER)));
    EXPECT_TRUE(parcel.WriteParcelable(nullptr));
    EXPECT_TRUE(parcel.WriteString("BundleX"));
    EXPECT_TRUE(parcel.WriteInt64(222));
    EXPECT_TRUE(parcel.WriteString("GroupX"));
    EXPECT_TRUE(parcel.WriteString("AppX"));
    parcel.RewindRead(0);
    std::unique_ptr<NotificationInfo> back(NotificationInfo::Unmarshalling(parcel));
    EXPECT_EQ(back, nullptr);
}

/**
 * @tc.name: NotificationInfo_FromJson_0100
 * @tc.desc: Verify FromJson full success.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_FromJson_0100, Function | SmallTest | Level1)
{
    nlohmann::json contentObj = { { "title", "FTitle" }, { "text", "FText" } };
    nlohmann::json obj = { { "hashCode", "FHash" },
        { "notificationSlotType", static_cast<int32_t>(NotificationConstant::SlotType::CONTENT_INFORMATION) },
        { "content", contentObj }, { "bundleName", "FBundle" }, { "deliveryTime", 333 }, { "groupName", "FGroup" },
        { "appName", "FApp" } };
    std::unique_ptr<NotificationInfo> info(NotificationInfo::FromJson(obj));
    EXPECT_NE(info, nullptr);
    EXPECT_EQ(info->GetHashCode(), "FHash");
    EXPECT_EQ(info->GetNotificationSlotType(), NotificationConstant::SlotType::CONTENT_INFORMATION);
    EXPECT_NE(info->GetNotificationExtensionContent(), nullptr);
    EXPECT_EQ(info->GetNotificationExtensionContent()->GetTitle(), "FTitle");
    EXPECT_EQ(info->GetNotificationExtensionContent()->GetText(), "FText");
    EXPECT_EQ(info->GetBundleName(), "FBundle");
    EXPECT_EQ(info->GetDeliveryTime(), 333);
    EXPECT_EQ(info->GetGroupName(), "FGroup");
    EXPECT_EQ(info->GetAppName(), "FApp");
}

/**
 * @tc.name: NotificationInfo_FromJson_0200
 * @tc.desc: Verify FromJson partial (missing optional fields & content -> content_ stays null).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_FromJson_0200, Function | SmallTest | Level1)
{
    nlohmann::json obj = { { "hashCode", "PHash" },
        { "notificationSlotType", static_cast<int32_t>(NotificationConstant::SlotType::CUSTOM) } };
    std::unique_ptr<NotificationInfo> info(NotificationInfo::FromJson(obj));
    EXPECT_NE(info, nullptr);
    EXPECT_EQ(info->GetHashCode(), "PHash");
    EXPECT_EQ(info->GetNotificationSlotType(), NotificationConstant::SlotType::CUSTOM);
    EXPECT_EQ(info->GetNotificationExtensionContent(), nullptr);
    EXPECT_EQ(info->GetBundleName(), "");
    EXPECT_EQ(info->GetAppName(), "");
    EXPECT_EQ(info->GetGroupName(), "");
    EXPECT_EQ(info->GetDeliveryTime(), 0);
}

/**
 * @tc.name: NotificationInfo_FromJson_Fail_0100
 * @tc.desc: Verify FromJson failure due to invalid json (not object).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_FromJson_Fail_0100, Function | SmallTest | Level1)
{
    nlohmann::json invalid = nullptr;
    std::unique_ptr<NotificationInfo> info(NotificationInfo::FromJson(invalid));
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: NotificationInfo_FromJson_Fail_0200
 * @tc.desc: Verify FromJson failure when content object is invalid (content key present but bad type).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationInfo_FromJson_Fail_0200, Function | SmallTest | Level1)
{
    nlohmann::json obj = { { "hashCode", "BadContentHash" },
        { "notificationSlotType", static_cast<int32_t>(NotificationConstant::SlotType::SERVICE_REMINDER) },
        { "content", nlohmann::json::array() } };
    std::unique_ptr<NotificationInfo> info(NotificationInfo::FromJson(obj));
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.name: NotificationExtensionContent_Dump_0100
 * @tc.desc: Verify Dump with title and text set.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_Dump_0100, Function | SmallTest | Level1)
{
    NotificationExtensionContent content;
    content.SetTitle("CTitle");
    content.SetText("CText");
    std::string dumpStr = content.Dump();
    EXPECT_NE(dumpStr.find("CTitle"), std::string::npos);
    EXPECT_NE(dumpStr.find("CText"), std::string::npos);
}

/**
 * @tc.name: NotificationExtensionContent_Dump_0200
 * @tc.desc: Verify Dump when fields empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_Dump_0200, Function | SmallTest | Level1)
{
    NotificationExtensionContent content;
    std::string dumpStr = content.Dump();
    EXPECT_NE(dumpStr.find("title ="), std::string::npos);
    EXPECT_NE(dumpStr.find(", text ="), std::string::npos);
}

/**
 * @tc.name: NotificationExtensionContent_ToJson_0100
 * @tc.desc: Verify ToJson success with fields set.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_ToJson_0100, Function | SmallTest | Level1)
{
    NotificationExtensionContent content;
    content.SetTitle("JTitle");
    content.SetText("JText");
    nlohmann::json obj;
    EXPECT_TRUE(content.ToJson(obj));
    EXPECT_TRUE(obj.is_object());
    EXPECT_EQ(obj["title"].get<std::string>(), "JTitle");
    EXPECT_EQ(obj["text"].get<std::string>(), "JText");
}

/**
 * @tc.name: NotificationExtensionContent_ToJson_0200
 * @tc.desc: Verify ToJson success with empty fields.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_ToJson_0200, Function | SmallTest | Level1)
{
    NotificationExtensionContent content;
    nlohmann::json obj;
    EXPECT_TRUE(content.ToJson(obj));
    EXPECT_TRUE(obj.is_object());
    EXPECT_TRUE(obj.contains("title"));
    EXPECT_TRUE(obj.contains("text"));
    EXPECT_EQ(obj["title"].get<std::string>(), "");
    EXPECT_EQ(obj["text"].get<std::string>(), "");
}

/**
 * @tc.name: NotificationExtensionContent_FromJson_0100
 * @tc.desc: Verify FromJson success with both fields.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_FromJson_0100, Function | SmallTest | Level1)
{
    nlohmann::json obj = { { "title", "FCTitle" }, { "text", "FCText" } };
    std::unique_ptr<NotificationExtensionContent> content(NotificationExtensionContent::FromJson(obj));
    EXPECT_NE(content, nullptr);
    EXPECT_EQ(content->GetTitle(), "FCTitle");
    EXPECT_EQ(content->GetText(), "FCText");
}

/**
 * @tc.name: NotificationExtensionContent_FromJson_0200
 * @tc.desc: Verify FromJson partial (only title).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_FromJson_0200, Function | SmallTest | Level1)
{
    nlohmann::json obj = { { "title", "OnlyTitle" } };
    std::unique_ptr<NotificationExtensionContent> content(NotificationExtensionContent::FromJson(obj));
    EXPECT_NE(content, nullptr);
    EXPECT_EQ(content->GetTitle(), "OnlyTitle");
    EXPECT_EQ(content->GetText(), "");
}

/**
 * @tc.name: NotificationExtensionContent_FromJson_Fail_0100
 * @tc.desc: Verify FromJson failure on null json.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_FromJson_Fail_0100, Function | SmallTest | Level1)
{
    nlohmann::json invalid = nullptr;
    std::unique_ptr<NotificationExtensionContent> content(NotificationExtensionContent::FromJson(invalid));
    EXPECT_EQ(content, nullptr);
}

/**
 * @tc.name: NotificationExtensionContent_FromJson_Fail_0200
 * @tc.desc: Verify FromJson failure on non-object (array) json.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, NotificationExtensionContent_FromJson_Fail_0200, Function | SmallTest | Level1)
{
    nlohmann::json invalid = nlohmann::json::array();
    std::unique_ptr<NotificationExtensionContent> content(NotificationExtensionContent::FromJson(invalid));
    EXPECT_EQ(content, nullptr);
}
}
}
