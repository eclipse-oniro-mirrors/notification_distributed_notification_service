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

#include "dialog_status_data.h"

#include "ans_log_wrapper.h"

namespace OHOS::Notification {
bool DialogStatusData::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt32(status_)) {
        ANS_LOGE("Failed to write status");
        return false;
    }
    return true;
}

DialogStatusData* DialogStatusData::Unmarshalling(Parcel& parcel)
{
    DialogStatusData* data = new (std::nothrow) DialogStatusData(
        static_cast<EnabledDialogStatus>(parcel.ReadInt32()));
    if (data == nullptr) {
        return nullptr;
    }
    return data;
}
} // namespace OHOS::Notification