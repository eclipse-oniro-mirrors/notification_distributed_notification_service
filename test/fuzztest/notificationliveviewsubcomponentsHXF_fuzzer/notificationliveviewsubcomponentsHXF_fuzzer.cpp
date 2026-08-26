/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "notificationliveviewsubcomponentsHXF_fuzzer.h"
#include "notification_capsule.h"
#include "notification_group_info.h"
#include "notification_icon_button.h"
#include "notification_progress.h"
#include "notification_unified_group_Info.h"
#include "notification_voice_content.h"
#include "parcel.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

namespace OHOS {
    namespace {
        constexpr uint8_t MAX_CAPSULE_BUTTONS = 8;
        constexpr int32_t PROGRESS_PROBE_MAX  = 300;
        constexpr int32_t MAX_LENGTH = 256;
        constexpr int32_t MAX_NUM = 128;
        constexpr int32_t MAX_NUMBER = 512;
        constexpr int32_t MAX_SIZE_TYPE = 16;
    }

    void FuzzUnifiedGroupInfo(FuzzedDataProvider *fdp)
    {
        Notification::NotificationUnifiedGroupInfo ugi;
        ugi.SetKey(fdp->ConsumeRandomLengthString(MAX_NUM));
        ugi.GetKey();
        ugi.SetTitle(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        ugi.GetTitle();
        ugi.SetContent(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        ugi.GetContent();
        ugi.SetSceneName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        ugi.GetSceneName();
        ugi.SetExtraInfo(nullptr);
        ugi.GetExtraInfo();
        ugi.Dump();

        Parcel p;
        if (ugi.Marshalling(p)) {
            Notification::NotificationUnifiedGroupInfo *r =
                Notification::NotificationUnifiedGroupInfo::Unmarshalling(p);
            delete r;
        }
    }

    void FuzzGroupInfo(FuzzedDataProvider *fdp)
    {
        Notification::NotificationGroupInfo gi;
        gi.SetGroupTitle(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        gi.GetGroupTitle();
        gi.SetIsGroupIcon(fdp->ConsumeBool());
        gi.GetIsGroupIcon();
        gi.Dump();

        Parcel p;
        if (gi.Marshalling(p)) {
            Notification::NotificationGroupInfo *r =
                Notification::NotificationGroupInfo::Unmarshalling(p);
            delete r;
        }

        nlohmann::json j;
        gi.ToJson(j);
        Notification::NotificationGroupInfo *rj =
            Notification::NotificationGroupInfo::FromJson(j);
        delete rj;
    }

    void FuzzVoiceContent(FuzzedDataProvider *fdp)
    {
        std::string voiceText = fdp->ConsumeRandomLengthString(MAX_NUMBER);
        Notification::NotificationVoiceContent vc;
        vc.SetTextContent(voiceText);
        vc.GetTextContent();
        vc.Dump();

        Parcel p;
        if (vc.Marshalling(p)) {
            Notification::NotificationVoiceContent *r =
                Notification::NotificationVoiceContent::Unmarshalling(p);
            delete r;
        }

        Notification::NotificationVoiceContent vc2(vc);
        vc2.GetTextContent();
    }

    void FuzzProgress(FuzzedDataProvider *fdp)
    {
        int32_t maxValue  = static_cast<int32_t>(fdp->ConsumeIntegral<uint8_t>() % PROGRESS_PROBE_MAX) - 1;
        int32_t curValue  = static_cast<int32_t>(fdp->ConsumeIntegral<uint8_t>() % PROGRESS_PROBE_MAX) - 1;
        bool isPercentage = fdp->ConsumeBool();

        Notification::NotificationProgress prog;
        prog.SetMaxValue(maxValue);
        prog.GetMaxValue();
        prog.SetCurrentValue(curValue);
        prog.GetCurrentValue();
        prog.SetIsPercentage(isPercentage);
        prog.GetIsPercentage();
        prog.Dump();

        Parcel p;
        if (prog.Marshalling(p)) {
            Notification::NotificationProgress *r =
                Notification::NotificationProgress::Unmarshalling(p);
            delete r;
        }

        nlohmann::json j;
        prog.ToJson(j);
        Notification::NotificationProgress *rj =
            Notification::NotificationProgress::FromJson(j);
        delete rj;
    }

    void FuzzCapsule(FuzzedDataProvider *fdp)
    {
        Notification::NotificationCapsule capsule;
        capsule.SetTitle(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        capsule.GetTitle();
        capsule.SetBackgroundColor(fdp->ConsumeRandomLengthString(MAX_SIZE_TYPE));
        capsule.GetBackgroundColor();
        capsule.SetContent(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        capsule.GetContent();
        capsule.SetTime(fdp->ConsumeIntegral<int32_t>());
        capsule.GetTime();

        uint8_t btnCount = fdp->ConsumeIntegral<uint8_t>() % MAX_CAPSULE_BUTTONS;
        std::vector<Notification::NotificationIconButton> buttons;
        for (uint8_t i = 0; i < btnCount; ++i) {
            Notification::NotificationIconButton btn;
            buttons.push_back(btn);
        }
        capsule.SetCapsuleButton(buttons);
        capsule.GetCapsuleButton();
        capsule.Dump();

        Parcel p;
        if (capsule.Marshalling(p)) {
            Notification::NotificationCapsule *r =
                Notification::NotificationCapsule::Unmarshalling(p);
            delete r;
        }

        nlohmann::json j;
        capsule.ToJson(j);
        Notification::NotificationCapsule *rj =
            Notification::NotificationCapsule::FromJson(j);
        delete rj;

        capsule.ResetIcon();
    }

    bool test(FuzzedDataProvider *fdp)
    {
        FuzzUnifiedGroupInfo(fdp);
        FuzzGroupInfo(fdp);
        FuzzVoiceContent(fdp);
        FuzzProgress(fdp);
        FuzzCapsule(fdp);
        return true;
    }
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::test(&fdp);
    return 0;
}
