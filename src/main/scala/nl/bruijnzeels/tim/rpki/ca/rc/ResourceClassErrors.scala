package nl.bruijnzeels.tim.rpki.ca.rc

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Error

sealed trait ResourceClassError extends Error

case object CannotAddChildWithOverclaimingResources extends ResourceClassError {
  def reason = "Can not add child with resources not held by resource class"
}