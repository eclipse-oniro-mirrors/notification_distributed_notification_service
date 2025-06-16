/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <securec.h>
#include "gtest/gtest.h"
#define private public
#include "remove_box.h"
#include "match_box.h"
#include "bundle_icon_box.h"
#include "batch_remove_box.h"
#include "notification_sync_box.h"
#include "request_box.h"
#include "response_box.h"
#include "state_box.h"
#include "ans_log_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class TlvBoxTest : public testing::Test {
public:
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.name   : Tlv box for batch remove.
 * @tc.number : TlvBoxTest_0100
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0100, Function | SmallTest | Level1)
{
    auto data = std::make_shared<BatchRemoveNotificationBox>();
    data->SetNotificationHashCode("123");
    data->SetNotificationSlotTypes("321");
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    BatchRemoveNotificationBox bacthBox = BatchRemoveNotificationBox(box);
    bacthBox.box_ = nullptr;
    EXPECT_EQ(bacthBox.SetNotificationHashCode("123"), false);
    EXPECT_EQ(bacthBox.SetNotificationSlotTypes("321"), false);
    EXPECT_EQ(bacthBox.Serialize(), false);
}

/**
 * @tc.name   : Tlv box for remove.
 * @tc.number : TlvBoxTest_0101
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0101, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotificationRemoveBox>();
    data->SetNotificationHashCode("123");
    data->setNotificationSlotType(1);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    NotificationRemoveBox removeBox = NotificationRemoveBox(box);
    removeBox.box_ = nullptr;
    EXPECT_EQ(removeBox.SetNotificationHashCode("123"), false);
    EXPECT_EQ(removeBox.setNotificationSlotType(1), false);
}

/**
 * @tc.name   : Tlv box for remove.
 * @tc.number : TlvBoxTest_0111
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0111, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotificationRemoveBox>();
    data->SetNotificationHashCode("123");
    data->setNotificationSlotType(1);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;
}

/**
 * @tc.name   : Tlv box for bundle icon.
 * @tc.number : TlvBoxTest_0102
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0102, Function | SmallTest | Level1)
{
    auto data = std::make_shared<BundleIconBox>();
    data->SetMessageType(BUNDLE_ICON_SYNC);
    data->SetIconSyncType(IconSyncType::REQUEST_BUNDLE_ICON);
    data->SetBundleList({"ohom.example.test"});
    data->SetLocalDeviceId("local_device");
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    int32_t intData;
    BundleIconBox iconBox = BundleIconBox(box);
    EXPECT_EQ(iconBox.box_->GetMessageType(intData), true);
    EXPECT_EQ(intData, BUNDLE_ICON_SYNC);
    EXPECT_EQ(iconBox.GetIconSyncType(intData), true);
    EXPECT_EQ(intData, IconSyncType::REQUEST_BUNDLE_ICON);
    std::string stringData;
    EXPECT_EQ(iconBox.GetLocalDeviceId(stringData), true);
    EXPECT_EQ(stringData, "local_device");
    std::vector<std::string> bundleList;
    EXPECT_EQ(iconBox.GetBundleList(bundleList), true);
    EXPECT_EQ(bundleList.empty(), false);
    iconBox.box_ = nullptr;
    EXPECT_EQ(iconBox.SetMessageType(BUNDLE_ICON_SYNC), false);
    EXPECT_EQ(iconBox.SetIconSyncType(IconSyncType::REQUEST_BUNDLE_ICON), false);
    EXPECT_EQ(iconBox.SetBundleList({"ohom.example.test"}), false);
    EXPECT_EQ(iconBox.SetLocalDeviceId("local_device"), false);
    EXPECT_EQ(iconBox.SetDataLength(1), false);
    std::unordered_map<std::string, std::string> bundles;
    bundles.insert({"123", "abc"});
    EXPECT_EQ(iconBox.SetBundlesIcon(bundles), false);

    std::unordered_map<std::string, std::string> receiveBundles;
    EXPECT_EQ(iconBox.GetIconSyncType(intData), false);
    EXPECT_EQ(iconBox.GetLocalDeviceId(stringData), false);
    EXPECT_EQ(iconBox.GetBundleList(bundleList), false);
    EXPECT_EQ(iconBox.GetDataLength(intData), false);
    EXPECT_EQ(iconBox.GetBundlesIcon(receiveBundles), false);
}

/**
 * @tc.name   : Tlv box for bundle icon.
 * @tc.number : TlvBoxTest_0103
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0103, Function | SmallTest | Level1)
{
    auto data = std::make_shared<BundleIconBox>();
    std::unordered_map<std::string, std::string> bundles;
    bundles.insert({"123", "abc"});
    data->SetBundlesIcon(bundles);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    bundles.clear();
    BundleIconBox iconBox = BundleIconBox(box);
    EXPECT_EQ(iconBox.GetBundlesIcon(bundles), true);
    EXPECT_EQ(bundles.empty(), false);
}

/**
 * @tc.name   : Tlv box for match.
 * @tc.number : TlvBoxTest_0104
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0104, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotifticationMatchBox>();
    data->SetPeerDeviceType(10);
    data->SetPeerDeviceId("peer_device");
    data->SetLocalDeviceType(16);
    data->SetLocalDeviceId("local_device");
    data->SetVersion(100);
    data->SetMatchType(1);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    int32_t intData;
    NotifticationMatchBox matchBox = NotifticationMatchBox(box);
    EXPECT_EQ(matchBox.GetPeerDeviceType(intData), true);
    EXPECT_EQ(intData, 10);
    EXPECT_EQ(matchBox.GetLocalDeviceType(intData), true);
    EXPECT_EQ(intData, 16);
    EXPECT_EQ(matchBox.GetVersion(intData), true);
    EXPECT_EQ(intData, 1000);
    EXPECT_EQ(matchBox.GetMatchType(intData), true);
    EXPECT_EQ(intData, 1);

    std::string strinigData;
    EXPECT_EQ(matchBox.GetPeerDeviceId(strinigData), true);
    EXPECT_EQ(strinigData, "peer_device");
    EXPECT_EQ(matchBox.GetLocalDeviceId(strinigData), true);
    EXPECT_EQ(strinigData, "local_device");
}

/**
 * @tc.name   : Tlv box for match.
 * @tc.number : TlvBoxTest_0105
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0105, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotifticationMatchBox>();
    data->SetPeerDeviceType(10);
    data->SetPeerDeviceId("peer_device");
    data->SetLocalDeviceType(16);
    data->SetLocalDeviceId("local_device");
    data->SetVersion(100);
    data->SetMatchType(1);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    int32_t intData;
    NotifticationMatchBox matchBox = NotifticationMatchBox(box);
    EXPECT_EQ(matchBox.GetPeerDeviceType(intData), true);
    EXPECT_EQ(intData, 10);
    EXPECT_EQ(matchBox.GetLocalDeviceType(intData), true);
    EXPECT_EQ(intData, 16);
    EXPECT_EQ(matchBox.GetVersion(intData), true);
    EXPECT_EQ(intData, 1000);
    EXPECT_EQ(matchBox.GetMatchType(intData), true);
    EXPECT_EQ(intData, 1);

    std::string strinigData;
    EXPECT_EQ(matchBox.GetPeerDeviceId(strinigData), true);
    EXPECT_EQ(strinigData, "peer_device");
    EXPECT_EQ(matchBox.GetLocalDeviceId(strinigData), true);
    EXPECT_EQ(strinigData, "local_device");
}

/**
 * @tc.name   : Tlv box for notification.
 * @tc.number : TlvBoxTest_0106
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0106, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotificationSyncBox>();
    data->SetLocalDeviceId("local_device");
    data->SetNotificationEmpty(false);
    data->SetNotificationList({"hasd_code"});
    int32_t type;
    data->box_->GetMessageType(type);
    EXPECT_EQ(type, SYNC_NOTIFICATION);
    data->box_ = nullptr;
    EXPECT_EQ(data->SetLocalDeviceId("local_device"), false);
    EXPECT_EQ(data->SetNotificationEmpty(false), false);
    EXPECT_EQ(data->SetNotificationList({"hasd_code"}), false);
}

/**
 * @tc.name   : Tlv box for notification request.
 * @tc.number : TlvBoxTest_0107
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0107, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotificationRequestBox>();
    EXPECT_EQ(data->SetNotificationHashCode("hashCode"), true);
    EXPECT_EQ(data->SetSlotType(0), true);
    EXPECT_EQ(data->SetContentType(0), true);
    EXPECT_EQ(data->SetReminderFlag(0), true);
    EXPECT_EQ(data->SetCreatorBundleName("bundleName"), true);
    EXPECT_EQ(data->SetNotificationTitle("title"), true);
    EXPECT_EQ(data->SetNotificationText("text"), true);
    EXPECT_EQ(data->SetNotificationAdditionalText("text"), true);
    EXPECT_EQ(data->SetNotificationBriefText("text"), true);
    EXPECT_EQ(data->SetNotificationExpandedTitle("text"), true);
    EXPECT_EQ(data->SetNotificationLongText("text"), true);
    EXPECT_EQ(data->SetAllLineLength(1), true);
    EXPECT_EQ(data->SetNotificationAllLines({"line"}), true);
    std::shared_ptr<Media::PixelMap> picture = std::make_shared<Media::PixelMap>();
    EXPECT_EQ(data->SetNotificationBigPicture(picture), true);
    EXPECT_EQ(data->SetNotificationActionName("actionName"), true);
    EXPECT_EQ(data->SetNotificationActionName("userInput"), true);
    EXPECT_EQ(data->SetSmallIcon(picture), true);
    EXPECT_EQ(data->SetBigIcon(picture, 17), true);
    EXPECT_EQ(data->SetOverlayIcon(picture, 17), true);
    std::vector<uint8_t> buffer = {2};
    EXPECT_EQ(data->SetCommonLiveView(buffer), true);
    EXPECT_EQ(data->SetFinishTime(12345), true);
    EXPECT_EQ(data->SetAutoDeleteTime(12345), true);
    EXPECT_EQ(data->SetAppMessageId("id"), true);
    EXPECT_EQ(data->SetAppIcon("appIcon"), true);
    EXPECT_EQ(data->SetAppName("appName"), true);
    EXPECT_EQ(data->SetAppLabel("appLabel"), true);
    EXPECT_EQ(data->SetAppIndex(0), true);
    EXPECT_EQ(data->SetNotificationUserId(100), true);
    EXPECT_EQ(data->SetDeviceUserId(100), true);
    EXPECT_EQ(data->SetDeviceId("abc"), true);
    EXPECT_EQ(data->SetNotificationUserInput("abc"), true);
    int32_t type;
    data->box_->GetMessageType(type);
    EXPECT_EQ(type, PUBLISH_NOTIFICATION);
}

/**
 * @tc.name   : Tlv box for response.
 * @tc.number : TlvBoxTest_0108
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0108, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotificationResponseBox>();
    data->SetMessageType(10);
    data->SetNotificationHashCode("hashCode");
    data->SetOperationEventId("eventId");
    data->SetActionName("actionName");
    data->SetUserInput("userInput");
    data->SetOperationType(1);
    data->SetMatchType(1);
    data->SetLocalDeviceId("deviceId");
    data->SetResponseResult(0);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    int32_t intData;
    NotificationResponseBox responseBox = NotificationResponseBox(box);
    EXPECT_EQ(responseBox.GetOperationType(intData), true);
    EXPECT_EQ(intData, 1);
    EXPECT_EQ(responseBox.GetMatchType(intData), true);
    EXPECT_EQ(intData, 1);
    EXPECT_EQ(responseBox.GetResponseResult(intData), true);
    EXPECT_EQ(intData, 0);

    std::string strinigData;
    EXPECT_EQ(responseBox.GetNotificationHashCode(strinigData), true);
    EXPECT_EQ(strinigData, "hashCode");
    EXPECT_EQ(responseBox.GetOperationEventId(strinigData), true);
    EXPECT_EQ(strinigData, "eventId");
    EXPECT_EQ(responseBox.GetActionName(strinigData), true);
    EXPECT_EQ(strinigData, "actionName");
    EXPECT_EQ(responseBox.GetUserInput(strinigData), true);
    EXPECT_EQ(strinigData, "userInput");
    EXPECT_EQ(responseBox.GetLocalDeviceId(strinigData), true);
    EXPECT_EQ(strinigData, "deviceId");
}

/**
 * @tc.name   : Tlv box for state box.
 * @tc.number : TlvBoxTest_0109
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0109, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotifticationStateBox>();
    data->box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_TYPE, "deviceType"));
    data->box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, "deviceId"));
    data->box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_STATUS, 0));
    data->box_->PutValue(std::make_shared<TlvItem>(LIVEVIEW_SYNC_ENABLE, true));
    data->box_->PutValue(std::make_shared<TlvItem>(NOTIFICATION_SYNC_ENABLE, true));

    auto dataMap = data->box_->TlvMap_;
    for (auto item : dataMap) {
        ANS_LOGI("TlvBoxTest_0109 %{public}d %{public}s.", item.first, reinterpret_cast<char*>(item.second->value_));
    }

    int32_t intData;
    EXPECT_EQ(data->GetState(intData), true);
    EXPECT_EQ(intData, 0);
    std::string strinigData;
    EXPECT_EQ(data->GetDeviceType(strinigData), true);
    EXPECT_EQ(data->GetDeviceId(strinigData), true);
    bool boolData;
    EXPECT_EQ(data->GetLiveViewEnable(boolData), true);
    EXPECT_EQ(boolData, true);
    EXPECT_EQ(data->GetNotificationEnable(boolData), true);
    EXPECT_EQ(boolData, true);
    data->box_ = nullptr;
    EXPECT_EQ(data->GetState(intData), false);
    EXPECT_EQ(data->GetDeviceType(strinigData), false);
    EXPECT_EQ(data->GetDeviceId(strinigData), false);
    EXPECT_EQ(data->GetLiveViewEnable(boolData), false);
    EXPECT_EQ(data->GetNotificationEnable(boolData), false);
}

/**
 * @tc.name   : Tlv box for notification request.
 * @tc.number : TlvBoxTest_0110
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0110, Function | SmallTest | Level1)
{
    auto data = std::make_shared<NotificationRequestBox>();
    data->box_ = nullptr;
    std::shared_ptr<Media::PixelMap> picture = std::make_shared<Media::PixelMap>();
    EXPECT_EQ(data->SetNotificationHashCode("hashCode"), false);
    EXPECT_EQ(data->SetSlotType(0), false);
    EXPECT_EQ(data->SetContentType(0), false);
    EXPECT_EQ(data->SetReminderFlag(0), false);
    EXPECT_EQ(data->SetCreatorBundleName("bundleName"), false);
    EXPECT_EQ(data->SetNotificationTitle("title"), false);
    EXPECT_EQ(data->SetNotificationText("text"), false);
    EXPECT_EQ(data->SetNotificationAdditionalText("text"), false);
    EXPECT_EQ(data->SetNotificationBriefText("text"), false);
    EXPECT_EQ(data->SetNotificationExpandedTitle("text"), false);
    EXPECT_EQ(data->SetNotificationLongText("text"), false);
    EXPECT_EQ(data->SetAllLineLength(1), false);
    EXPECT_EQ(data->SetNotificationAllLines({"line"}), false);
    EXPECT_EQ(data->SetNotificationBigPicture(picture), true);
    EXPECT_EQ(data->SetNotificationActionName("actionName"), false);
    EXPECT_EQ(data->SetNotificationActionName("userInput"), false);
    EXPECT_EQ(data->SetSmallIcon(picture), false);
    EXPECT_EQ(data->SetBigIcon(picture, 17), false);
    EXPECT_EQ(data->SetOverlayIcon(picture, 17), false);
    std::vector<uint8_t> buffer = {2};
    EXPECT_EQ(data->SetCommonLiveView(buffer), false);
    EXPECT_EQ(data->SetFinishTime(12345), false);
    EXPECT_EQ(data->SetAutoDeleteTime(12345), false);
    EXPECT_EQ(data->SetAppMessageId("id"), false);
    EXPECT_EQ(data->SetAppIcon("appIcon"), false);
    EXPECT_EQ(data->SetAppName("appName"), false);
    EXPECT_EQ(data->SetAppLabel("appLabel"), false);
    EXPECT_EQ(data->SetAppIndex(0), false);
    EXPECT_EQ(data->SetNotificationUserId(100), false);
    EXPECT_EQ(data->SetDeviceUserId(100), false);
    EXPECT_EQ(data->SetDeviceId("abc"), false);
}

/**
 * @tc.name   : Tlv box for response.
 * @tc.number : TlvBoxTest_0112
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0112, Function | SmallTest | Level1)
{
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    int32_t intData;
    std::string strinigData;
    NotificationResponseBox responseBox = NotificationResponseBox(box);
    responseBox.box_ = nullptr;
    EXPECT_EQ(responseBox.SetMessageType(10), false);
    EXPECT_EQ(responseBox.SetNotificationHashCode("hashCode"), false);
    EXPECT_EQ(responseBox.SetOperationEventId("eventId"), false);
    EXPECT_EQ(responseBox.SetActionName("actionName"), false);
    EXPECT_EQ(responseBox.SetUserInput("userInput"), false);
    EXPECT_EQ(responseBox.SetOperationType(1), false);
    EXPECT_EQ(responseBox.SetMatchType(1), false);
    EXPECT_EQ(responseBox.SetLocalDeviceId("deviceId"), false);
    EXPECT_EQ(responseBox.SetResponseResult(0), false);

    EXPECT_EQ(responseBox.GetOperationType(intData), false);
    EXPECT_EQ(responseBox.GetMatchType(intData), false);
    EXPECT_EQ(responseBox.GetResponseResult(intData), false);
    EXPECT_EQ(responseBox.GetNotificationHashCode(strinigData), false);
    EXPECT_EQ(responseBox.GetOperationEventId(strinigData), false);
    EXPECT_EQ(responseBox.GetActionName(strinigData), false);
    EXPECT_EQ(responseBox.GetUserInput(strinigData), false);
    EXPECT_EQ(responseBox.GetLocalDeviceId(strinigData), false);
}

/**
 * @tc.name   : Tlv box for match.
 * @tc.number : TlvBoxTest_0113
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_0113, Function | SmallTest | Level1)
{
    int32_t intData;
    std::string strinigData;
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    NotifticationMatchBox matchBox = NotifticationMatchBox(box);
    matchBox.box_ = nullptr;
    EXPECT_EQ(matchBox.SetPeerDeviceType(10), false);
    EXPECT_EQ(matchBox.SetLocalDeviceType(16), false);
    EXPECT_EQ(matchBox.SetVersion(100), false);
    EXPECT_EQ(matchBox.SetMatchType(1), false);
    EXPECT_EQ(matchBox.SetPeerDeviceId("peer_device"), false);
    EXPECT_EQ(matchBox.SetLocalDeviceId("local_device"), false);

    EXPECT_EQ(matchBox.GetPeerDeviceType(intData), false);
    EXPECT_EQ(matchBox.GetLocalDeviceType(intData), false);
    EXPECT_EQ(matchBox.GetVersion(intData), false);
    EXPECT_EQ(matchBox.GetMatchType(intData), false);
    EXPECT_EQ(matchBox.GetPeerDeviceId(strinigData), false);
    EXPECT_EQ(matchBox.GetLocalDeviceId(strinigData), false);
}
}  // namespace Notification
}  // namespace OHOS
