/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#define protected public
#include "notification_basic_content.h"
#include "notification_content.h"
#include "notification_json_convert.h"
#include "notification_normal_content.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationContentTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: NotificationContentMarshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationContentMarshalling_0100, Level1)
{
    Parcel parcel;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    NotificationContent notificationContent(normalContent);
    auto result = notificationContent.Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: NotificationContentReadFromParcel_0100
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationContentReadFromParcel_0100, Level1)
{
    Parcel parcel;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    NotificationContent notificationContent(normalContent);
    auto result = notificationContent.ReadFromParcel(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: NotificationBasicContentGetAdditionalText_0100
 * @tc.desc: GetAdditionalText
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentGetAdditionalText_0100, Level1)
{
    std::string additionalText = "test";
    NotificationBasicContent notificationBasicContent;
    notificationBasicContent.SetAdditionalText(additionalText);
    auto result = notificationBasicContent.GetAdditionalText();
    EXPECT_EQ(result, additionalText);
}

/**
 * @tc.name: NotificationBasicContentGetText_0100
 * @tc.desc: GetText
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentGetText_0100, Level1)
{
    std::string Text = "test";
    NotificationBasicContent notificationBasicContent;
    notificationBasicContent.SetText(Text);
    auto result = notificationBasicContent.GetText();
    EXPECT_EQ(result, Text);
}

/**
 * @tc.name: NotificationBasicContentGetTitle_0100
 * @tc.desc: GetTitle
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentGetTitle_0100, Level1)
{
    std::string title = "titleTest";
    NotificationBasicContent notificationBasicContent;
    notificationBasicContent.SetTitle(title);
    auto result = notificationBasicContent.GetTitle();
    EXPECT_EQ(result, title);
    std::vector<std::pair<std::string, std::string>> structuredText;
    structuredText.emplace_back("123", "abc");
    notificationBasicContent.SetStructuredText(structuredText);
    EXPECT_EQ(notificationBasicContent.GetStructuredText().front().first, "123");
}

/**
 * @tc.name: NotificationBasicContentMarshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentMarshalling_0100, Level1)
{
    Parcel parcel;
    NotificationBasicContent notificationBasicContent;
    auto result = notificationBasicContent.Marshalling(parcel);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: NotificationContentReadFromParcel_0200
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI665WK
 */
HWTEST_F(NotificationContentTest, NotificationContentReadFromParcel_0200, Level1)
{
    std::shared_ptr<NotificationNormalContent> normalContent0 = nullptr;
    NotificationContent notificationContent0(normalContent0);

    std::shared_ptr<NotificationLongTextContent> longTextContent = nullptr;
    NotificationContent notificationContent1(longTextContent);

    std::shared_ptr<NotificationPictureContent> pictureContent = nullptr;
    NotificationContent notificationContent2(pictureContent);

    std::shared_ptr<NotificationConversationalContent> conversationContent = nullptr;
    NotificationContent notificationContent3(conversationContent);

    std::shared_ptr<NotificationMultiLineContent> multiLineContent = nullptr;
    NotificationContent notificationContent4(multiLineContent);

    std::shared_ptr<NotificationMediaContent> mediaContent = nullptr;
    NotificationContent notificationContent5(mediaContent);

    std::shared_ptr<NotificationLiveViewContent> liveViewContent = nullptr;
    NotificationContent notificationContent6(liveViewContent);

    std::shared_ptr<NotificationLocalLiveViewContent> localLiveViewContent = nullptr;
    NotificationContent notificationContent7(localLiveViewContent);

    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    NotificationContent notificationContent(normalContent);
    auto result = notificationContent.GetContentType();
    EXPECT_EQ(result, NotificationContent::Type::BASIC_TEXT);

    Parcel parcel;
    auto result1 = notificationContent.ReadFromParcel(parcel);
    EXPECT_EQ(result1, true);
}

/**
 * @tc.name: NotificationContentReadFromParcel_0300
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI665WK
 */
HWTEST_F(NotificationContentTest, NotificationContentReadFromParcel_0300, Level1)
{
    std::shared_ptr<NotificationConversationalContent> conversationContent =
        std::make_shared<NotificationConversationalContent>();
    NotificationContent notificationContent(conversationContent);
    auto result = notificationContent.GetContentType();
    EXPECT_EQ(result, NotificationContent::Type::CONVERSATION);

    Parcel parcel;
    auto result1 = notificationContent.ReadFromParcel(parcel);
    EXPECT_EQ(result1, true);
}

/**
 * @tc.name: NotificationContentReadFromParcel_0400
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI665WK
 */
HWTEST_F(NotificationContentTest, NotificationContentReadFromParcel_0400, Level1)
{
    std::shared_ptr<NotificationPictureContent> pictureContent = std::make_shared<NotificationPictureContent>();
    NotificationContent notificationContent(pictureContent);
    auto result = notificationContent.GetContentType();
    EXPECT_EQ(result, NotificationContent::Type::PICTURE);

    Parcel parcel;
    auto result1 = notificationContent.ReadFromParcel(parcel);
    EXPECT_EQ(result1, true);
}

/**
 * @tc.name: NotificationContentReadFromParcel_0500
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI665WK
 */
HWTEST_F(NotificationContentTest, NotificationContentReadFromParcel_0500, Level1)
{
    std::shared_ptr<NotificationMultiLineContent> multiLineContent = std::make_shared<NotificationMultiLineContent>();
    NotificationContent notificationContent(multiLineContent);
    auto result = notificationContent.GetContentType();
    EXPECT_EQ(result, NotificationContent::Type::MULTILINE);

    Parcel parcel;
    auto result1 = notificationContent.ReadFromParcel(parcel);
    EXPECT_EQ(result1, true);
}

/**
 * @tc.name: NotificationContentReadFromParcel_0600
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI665WK
 */
HWTEST_F(NotificationContentTest, NotificationContentReadFromParcel_0600, Level1)
{
    std::shared_ptr<NotificationMediaContent> mediaContent = std::make_shared<NotificationMediaContent>();
    NotificationContent notificationContent(mediaContent);
    auto result = notificationContent.GetContentType();
    EXPECT_EQ(result, NotificationContent::Type::MEDIA);

    Parcel parcel;
    auto result1 = notificationContent.ReadFromParcel(parcel);
    EXPECT_EQ(result1, true);
    notificationContent.Unmarshalling(parcel);
}

/**
 * @tc.name: ConvertJsonToContent_0100
 * @tc.desc: ConvertJsonToContent
 * @tc.type: FUNC
 * @tc.require: issueI665WK
 */
HWTEST_F(NotificationContentTest, ConvertJsonToContent_0100, Level1)
{
    std::shared_ptr<NotificationMediaContent> mediaContent = std::make_shared<NotificationMediaContent>();
    NotificationContent notificationContent(mediaContent);

    nlohmann::json jsonObject;
    auto result1 = notificationContent.ConvertJsonToContent(nullptr, jsonObject);
    EXPECT_EQ(result1, false);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, FromJson_00002, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationMediaContent> mediaContent = std::make_shared<NotificationMediaContent>();
    NotificationContent notificationContent(mediaContent);
    nlohmann::json jsonObject = nlohmann::json{"processName", "soundEnabled", "name", "arrivedTime1"};
    notificationContent.FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(notificationContent.FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, FromJson_00003, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationMediaContent> mediaContent = std::make_shared<NotificationMediaContent>();
    NotificationContent notificationContent(mediaContent);
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    auto result = notificationContent.FromJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, FromJson_00004, Function | SmallTest | Level1)
{
    NotificationContent content;
    nlohmann::json jsonObject = nlohmann::json{{"contentType", 1}, {"content", {}}};
    EXPECT_EQ(content.FromJson(jsonObject), nullptr);

    jsonObject["content"] = {{"text", "test"}, {"title", "testTitle"}};
    jsonObject["contentType"] = NotificationContent::Type::BASIC_TEXT;
    EXPECT_NE(content.FromJson(jsonObject), nullptr);

    jsonObject["contentType"] = NotificationContent::Type::CONVERSATION;
    EXPECT_NE(content.FromJson(jsonObject), nullptr);

    jsonObject["contentType"] = NotificationContent::Type::LONG_TEXT;
    EXPECT_NE(content.FromJson(jsonObject), nullptr);

    jsonObject["contentType"] = NotificationContent::Type::MULTILINE;
    EXPECT_NE(content.FromJson(jsonObject), nullptr);

    jsonObject["contentType"] = NotificationContent::Type::PICTURE;
    EXPECT_NE(content.FromJson(jsonObject), nullptr);

    jsonObject["contentType"] = NotificationContent::Type::LOCAL_LIVE_VIEW;
    EXPECT_NE(content.FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ToJson_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationMediaContent> mediaContent = nullptr;
    NotificationContent notificationContent(mediaContent);
    std::shared_ptr<NotificationBasicContent> result = notificationContent.GetNotificationContent();
    EXPECT_EQ(result, nullptr);
    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    bool result2 = notificationContent.ToJson(jsonObject);
    EXPECT_EQ(result2, false);
}

/**
 * @tc.name: NotificationContentMarshalling_0200
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationContentMarshalling_0200, Level1)
{
    std::shared_ptr<NotificationNormalContent> normalContent = nullptr;
    auto sptr1 = std::make_shared<NotificationContent>(normalContent);
    EXPECT_EQ(sptr1->GetNotificationContent(), nullptr);
    std::shared_ptr<NotificationLongTextContent> longTextContent = nullptr;
    auto sptr2 = std::make_shared<NotificationContent>(longTextContent);
    EXPECT_EQ(sptr2->GetNotificationContent(), nullptr);
    std::shared_ptr<NotificationPictureContent> pictureContent = nullptr;
    auto sptr3 = std::make_shared<NotificationContent>(pictureContent);
    EXPECT_EQ(sptr3->GetNotificationContent(), nullptr);
    std::shared_ptr<NotificationConversationalContent> conversationContent = nullptr;
    auto sptr4 = std::make_shared<NotificationContent>(conversationContent);
    EXPECT_EQ(sptr4->GetNotificationContent(), nullptr);
    std::shared_ptr<NotificationMultiLineContent> multiLineContent = nullptr;
    auto sptr5 = std::make_shared<NotificationContent>(multiLineContent);
    EXPECT_EQ(sptr5->GetNotificationContent(), nullptr);
    std::shared_ptr<NotificationMediaContent> mediaContent = nullptr;
    auto sptr6 = std::make_shared<NotificationContent>(mediaContent);
    EXPECT_EQ(sptr6->GetNotificationContent(), nullptr);
}

/**
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ToJson_00002, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    NotificationContent notificationContent(normalContent);

    nlohmann::json jsonObject = nlohmann::json{
        {"processName", "process6"}, {"APL", 1},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    bool result2 = notificationContent.ToJson(jsonObject);
    EXPECT_EQ(result2, true);
}

/**
 * @tc.name: NotificationBasicContentReadFromJson_00001
 * @tc.desc: GetAdditionalText
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, NotificationBasicContentReadFromJson_00001, Level1)
{
    auto notificationBasicContent = std::make_shared<NotificationBasicContent>();
    nlohmann::json jsonObject = nlohmann::json{
        {"text", "test"},
        {"title", "test"},
        {"additionalText", "test"}};
    notificationBasicContent->ReadFromJson(jsonObject);
    EXPECT_EQ(notificationBasicContent->GetText(), "test");
    EXPECT_EQ(notificationBasicContent->GetTitle(), "test");
    EXPECT_EQ(notificationBasicContent->GetAdditionalText(), "test");
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, Unmarshalling_00001, Level1)
{
    auto normalContent = std::make_shared<NotificationNormalContent>();
    NotificationContent content(normalContent);

    Parcel parcel;
    EXPECT_EQ(content.Marshalling(parcel), true);
    EXPECT_NE(content.Unmarshalling(parcel), nullptr);

    auto conversationalContent = std::make_shared<NotificationConversationalContent>();
    NotificationContent content1(conversationalContent);
    EXPECT_EQ(content1.Marshalling(parcel), true);
    EXPECT_NE(content1.Unmarshalling(parcel), nullptr);

    auto longContent = std::make_shared<NotificationLongTextContent>();
    NotificationContent content2(longContent);
    EXPECT_EQ(content2.Marshalling(parcel), true);
    EXPECT_NE(content2.Unmarshalling(parcel), nullptr);

    auto pictureContent = std::make_shared<NotificationPictureContent>();
    NotificationContent content3(pictureContent);
    EXPECT_EQ(content3.Marshalling(parcel), true);
    EXPECT_NE(content3.Unmarshalling(parcel), nullptr);

    auto mediaContent = std::make_shared<NotificationMediaContent>();
    NotificationContent content4(mediaContent);
    EXPECT_EQ(content4.Marshalling(parcel), true);
    EXPECT_NE(content4.Unmarshalling(parcel), nullptr);

    auto multiLineContent = std::make_shared<NotificationMultiLineContent>();
    NotificationContent content5(multiLineContent);
    EXPECT_EQ(content5.Marshalling(parcel), true);
    EXPECT_NE(content5.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: Unmarshalling_00002
 * @tc.desc: Test Unmarshalling
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, Unmarshalling_00002, Level1)
{
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    NotificationContent content(localLiveViewContent);

    Parcel parcel;
    EXPECT_EQ(content.Marshalling(parcel), true);
    EXPECT_NE(content.Unmarshalling(parcel), nullptr);

    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    NotificationContent content1(liveViewContent);
    EXPECT_EQ(content1.Marshalling(parcel), true);
    EXPECT_NE(content1.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: ReadFromParcel_00700
 * @tc.desc: Test ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, ReadFromParcel_00700, Level1)
{
    Parcel parcel;
    parcel.WriteBool(100);
    parcel.WriteBool(true);
    NotificationContent notificationContent;
    bool res = notificationContent.ReadFromParcel(parcel);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: ConvertJsonToContent_00200
 * @tc.desc: Test ConvertJsonToContent
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, ConvertJsonToContent_00200, Level1)
{
    NotificationContent notificationContent;
    nlohmann::json jsonObject = nlohmann::json{{"contentType", "test"}};
    sptr<NotificationContent> contentSptr(new NotificationContent());
    bool res = notificationContent.ConvertJsonToContent(contentSptr, jsonObject);
    ASSERT_FALSE(res);

    jsonObject = nlohmann::json{{"contentType", 999}, {"content", "test"}};
    res = notificationContent.ConvertJsonToContent(contentSptr, jsonObject);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: GetContentTypeByString_00100
 * @tc.desc: Test GetContentTypeByString_00100
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, GetContentTypeByString_00100, Level1)
{
    NotificationContent notificationContent;
    NotificationContent::Type contentType;
    bool res = notificationContent.GetContentTypeByString("1111", contentType);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: ConvertJsonToContent_00300
 * @tc.desc: Test ConvertJsonToContent with missing contentType field.
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, ConvertJsonToContent_00300, Level1)
{
    NotificationContent notificationContent;
    nlohmann::json jsonObject = nlohmann::json{{"content", "test"}};
    sptr<NotificationContent> contentSptr(new NotificationContent());
    bool res = notificationContent.ConvertJsonToContent(contentSptr, jsonObject);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: ConvertJsonToContent_00400
 * @tc.desc: Test ConvertJsonToContent with missing content field.
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, ConvertJsonToContent_00400, Level1)
{
    NotificationContent notificationContent;
    nlohmann::json jsonObject = nlohmann::json{{"contentType", 1}};
    sptr<NotificationContent> contentSptr(new NotificationContent());
    bool res = notificationContent.ConvertJsonToContent(contentSptr, jsonObject);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: ConvertJsonToContent_00500
 * @tc.desc: Test ConvertJsonToContent with empty json object.
 * @tc.type: FUNC
 * @tc.require: issueI5S0ZS
 */
HWTEST_F(NotificationContentTest, ConvertJsonToContent_00500, Level1)
{
    NotificationContent notificationContent;
    nlohmann::json jsonObject = nlohmann::json{};
    sptr<NotificationContent> contentSptr(new NotificationContent());
    bool res = notificationContent.ConvertJsonToContent(contentSptr, jsonObject);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: ConvertFromJsonString_00100
 * @tc.desc: Test ConvertFromJsonString with invalid JSON string (should not crash).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ConvertFromJsonString_00100, Level1)
{
    auto *result = NotificationJsonConverter::ConvertFromJsonString<NotificationNormalContent>("invalid json");
    EXPECT_EQ(result, nullptr);
    delete result;
}

/**
 * @tc.name: ConvertFromJsonString_00200
 * @tc.desc: Test ConvertFromJsonString with empty string.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ConvertFromJsonString_00200, Level1)
{
    auto *result = NotificationJsonConverter::ConvertFromJsonString<NotificationNormalContent>("");
    EXPECT_EQ(result, nullptr);
    delete result;
}

/**
 * @tc.name: ConvertFromJsonString_00300
 * @tc.desc: Test ConvertFromJsonString with non-object JSON (array).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ConvertFromJsonString_00300, Level1)
{
    auto *result = NotificationJsonConverter::ConvertFromJsonString<NotificationNormalContent>("[1, 2, 3]");
    EXPECT_EQ(result, nullptr);
    delete result;
}

/**
 * @tc.name: ReadFromJson_StructuredText_00100
 * @tc.desc: Test ReadFromJson with structuredText containing non-string values (should skip them).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ReadFromJson_StructuredText_00100, Level1)
{
    NotificationBasicContent content;
    nlohmann::json jsonObject = nlohmann::json{
        {"text", "test"},
        {"title", "title"},
        {"structuredText", {{"key1", "valid"}, {"key2", 123}, {"key3", true}, {"key4", "end"}}}};
    content.ReadFromJson(jsonObject);
    EXPECT_EQ(content.GetText(), "test");
    EXPECT_EQ(content.GetTitle(), "title");
}

/**
 * @tc.name: ReadFromJson_StructuredText_00200
 * @tc.desc: Test ReadFromJson with structuredText as non-object (should be ignored).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ReadFromJson_StructuredText_00200, Level1)
{
    NotificationBasicContent content;
    nlohmann::json jsonObject = nlohmann::json{
        {"text", "test"},
        {"structuredText", "not_an_object"}};
    content.ReadFromJson(jsonObject);
    EXPECT_EQ(content.GetText(), "test");
}

/**
 * @tc.name: ReadFromParcel_LiveViewNull_00100
 * @tc.desc: Test ReadFromParcel returns false when contentType is LIVE_VIEW but content parcelable is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationContentTest, ReadFromParcel_LiveViewNull_00100, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    parcel.WriteBool(true);
    parcel.WriteInt32(-1);
    NotificationContent content;
    EXPECT_EQ(content.ReadFromParcel(parcel), false);
}
}
}
