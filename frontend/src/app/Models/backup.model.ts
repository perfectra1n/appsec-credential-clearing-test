/*
 * Copyright (c) 2014-2020 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

export interface Backup {
  continueCode?: string
  language?: string
  banners?: { welcomeBannerStatus?: string; cookieConsentStatus?: string }
  scoreBoard?: { showOnlyTutorialChallenges?: string; displayedChallengeCategories?: string; displayedDifficulties?: string; showDisabledChallenges?: string; showSolvedChallenges?: string }
}
