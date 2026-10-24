// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_aggregate_descriptions.h"

#include <array>

namespace ua::server::aggregates
{

namespace
{

constexpr std::array germanDescriptions{
  StandardAggregateDescription{ObjectId::AggregateFunction_Interpolative,
    "Zu Beginn jedes Intervalls den berechneten Wert aus den Datenpunkten auf beiden Seiten des "
    "angeforderten Zeitstempels ermitteln."},
  StandardAggregateDescription{
    ObjectId::AggregateFunction_Average, "Den Mittelwert der Daten \u00fcber das Intervall ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_TimeAverage,
    "Den zeitgewichteten Mittelwert der Daten \u00fcber das Intervall unter Verwendung interpolierter "
    "Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Total,
    "Das Zeitintegral der Daten \u00fcber das Intervall unter Verwendung interpolierter Begrenzungswerte "
    "ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Minimum,
    "Den kleinsten Rohwert im Intervall mit dem Zeitstempel des Intervallbeginns ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Maximum,
    "Den gr\u00f6\u00dften Rohwert im Intervall mit dem Zeitstempel des Intervallbeginns ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_MinimumActualTime,
    "Den kleinsten Wert im Intervall und den Zeitstempel des kleinsten Werts ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_MaximumActualTime,
    "Den gr\u00f6\u00dften Wert im Intervall und den Zeitstempel des gr\u00f6\u00dften Werts ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Range,
    "Die Differenz zwischen dem kleinsten und dem gr\u00f6\u00dften Wert im Intervall ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_AnnotationCount,
    "Die Anzahl der Annotationen im Intervall ermitteln; gilt nur f\u00fcr historische Aggregate."},
  StandardAggregateDescription{
    ObjectId::AggregateFunction_Count, "Die Anzahl der Rohwerte im Intervall ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_NumberOfTransitions,
    "Die Anzahl der Wechsel zwischen einem Null- und einem Nichtnullzustand im Intervall ermitteln."},
  StandardAggregateDescription{
    ObjectId::AggregateFunction_Start, "Den Wert am Beginn des Intervalls ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_End, "Den Wert am Ende des Intervalls ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Delta,
    "Die Differenz zwischen dem Wert am Beginn und dem Wert am Ende des Intervalls ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_DurationGood,
    "Die Gesamtdauer im Intervall ermitteln, w\u00e4hrend der die Daten den Status Good besitzen."},
  StandardAggregateDescription{ObjectId::AggregateFunction_DurationBad,
    "Die Gesamtdauer im Intervall ermitteln, w\u00e4hrend der die Daten den Status Bad besitzen."},
  StandardAggregateDescription{ObjectId::AggregateFunction_PercentGood,
    "Den prozentualen Anteil des Intervalls ermitteln, w\u00e4hrend dessen die Daten den Status Good "
    "besitzen."},
  StandardAggregateDescription{ObjectId::AggregateFunction_PercentBad,
    "Den prozentualen Anteil des Intervalls ermitteln, w\u00e4hrend dessen die Daten den Status Bad "
    "besitzen."},
  StandardAggregateDescription{ObjectId::AggregateFunction_WorstQuality,
    "Den schlechtesten StatusCode der Daten im Intervall ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_TimeAverage2,
    "Den zeitgewichteten Mittelwert der Daten \u00fcber das Intervall unter Verwendung einfacher "
    "Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Minimum2,
    "Den kleinsten Wert im Intervall einschlie\u00dflich der einfachen Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Maximum2,
    "Den gr\u00f6\u00dften Wert im Intervall einschlie\u00dflich der einfachen Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Range2,
    "Die Differenz zwischen Minimum2 und Maximum2 im Intervall ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_WorstQuality2,
    "Den schlechtesten StatusCode der Daten im Intervall einschlie\u00dflich der einfachen "
    "Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_Total2,
    "Das Zeitintegral der Daten \u00fcber das Intervall unter Verwendung einfacher Begrenzungswerte "
    "ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_MinimumActualTime2,
    "Den kleinsten Wert mit seinem tats\u00e4chlichen Zeitstempel einschlie\u00dflich der einfachen "
    "Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_MaximumActualTime2,
    "Den gr\u00f6\u00dften Wert mit seinem tats\u00e4chlichen Zeitstempel einschlie\u00dflich der einfachen "
    "Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_DurationInStateZero,
    "Die Dauer eines booleschen oder numerischen Nullzustands unter Verwendung einfacher "
    "Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_DurationInStateNonZero,
    "Die Dauer eines booleschen oder numerischen Nichtnullzustands unter Verwendung einfacher "
    "Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_StandardDeviationSample,
    "Die Standardabweichung des Intervalls f\u00fcr eine Stichprobe der Grundgesamtheit mit dem Teiler "
    "n-1 ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_StandardDeviationPopulation,
    "Die Standardabweichung des Intervalls f\u00fcr die vollst\u00e4ndige Grundgesamtheit "
    "einschlie\u00dflich "
    "einfacher Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_VarianceSample,
    "Die Varianz des Intervalls entsprechend StandardDeviationSample ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_VariancePopulation,
    "Die Varianz des Intervalls entsprechend StandardDeviationPopulation ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_StartBound,
    "Den Wert am Beginn des Intervalls unter Verwendung einfacher Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_EndBound,
    "Den Wert am Ende des Intervalls unter Verwendung einfacher Begrenzungswerte ermitteln."},
  StandardAggregateDescription{ObjectId::AggregateFunction_DeltaBounds,
    "Die Differenz zwischen StartBound und EndBound unter Verwendung einfacher Begrenzungswerte "
    "ermitteln."},
};

}  // namespace

std::span<const StandardAggregateDescription> standard_aggregate_descriptions(
  std::string_view language) noexcept
{
  if (language == "de")
  {
    return germanDescriptions;
  }
  return {};
}

}  // namespace ua::server::aggregates
