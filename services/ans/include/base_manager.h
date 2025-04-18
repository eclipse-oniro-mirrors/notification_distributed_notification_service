/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_BASE_MANAGER_H
#define BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_BASE_MANAGER_H

#include "ans_const_define.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Notification {
class BaseManager {
protected:
    template<typename T>
    bool WriteParcelableVector(const std::vector<sptr<T>> &parcelableVector, MessageParcel &reply, ErrCode &result)
    {
        if (!reply.WriteInt32(result)) {
            ANS_LOGE("write result failed, ErrCode=%{public}d", result);
            return false;
        }

        if (!reply.WriteInt32(parcelableVector.size())) {
            ANS_LOGE("write ParcelableVector size failed");
            return false;
        }

        for (auto &parcelable : parcelableVector) {
            if (!reply.WriteStrongParcelable(parcelable)) {
                ANS_LOGE("write ParcelableVector failed");
                return false;
            }
        }
        return true;
    }

    template<typename T>
    bool ReadParcelableVector(std::vector<sptr<T>> &parcelableInfos, MessageParcel &data)
    {
        int32_t infoSize = 0;
        if (!data.ReadInt32(infoSize)) {
            ANS_LOGE("Failed to read Parcelable size.");
            return false;
        }

        parcelableInfos.clear();
        infoSize = (infoSize < MAX_PARCELABLE_VECTOR_NUM) ? infoSize : MAX_PARCELABLE_VECTOR_NUM;
        for (int32_t index = 0; index < infoSize; index++) {
            sptr<T> info = data.ReadStrongParcelable<T>();
            if (info == nullptr) {
                ANS_LOGE("Failed to read Parcelable infos.");
                return false;
            }
            parcelableInfos.emplace_back(info);
        }

        return true;
    }
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_BASE_MANAGER_H
