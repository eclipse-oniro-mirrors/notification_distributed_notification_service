/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_DIALOG_CALLBACK_INTERFACE_H
#define BASE_NOTIFICATION_ANS_DIALOG_CALLBACK_INTERFACE_H

#include "iremote_broker.h"

#include "nocopyable.h"
#include "parcel.h"

namespace OHOS::Notification {

enum class EnabledDialogStatus {
    ALLOW_CLICKED,
    DENY_CLICKED,
    CRASHED
};

class DialogStatusData : public Parcelable {
public:
    explicit DialogStatusData(EnabledDialogStatus status): status_(static_cast<int32_t>(status)) {}

    bool Marshalling(Parcel &parcel) const override;
    static DialogStatusData* Unmarshalling(Parcel &parcel);

    inline int32_t GetStatus() const { return status_; }

private:
    int32_t status_;
};

class AnsDialogCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Notification.AnsDialogCallback");

    AnsDialogCallback() = default;
    ~AnsDialogCallback() override = default;
    DISALLOW_COPY_AND_MOVE(AnsDialogCallback);

    virtual void OnDialogStatusChanged(const DialogStatusData& statusData) = 0;

    enum {
        // ipc id for OnDialogStatusChanged
        ON_DIALOG_STATUS_CHANGED = 1,
    };
};
} // namespace OHOS::Notification

#endif // BASE_NOTIFICATION_ANS_DIALOG_CALLBACK_INTERFACE_H
