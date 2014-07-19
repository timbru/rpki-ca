package nl.bruijnzeels.tim.rpki.ca.rc

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Error
import java.util.UUID
import net.ripe.ipresource.IpResourceSet

trait ResourceClassError extends Error

case object CannotAddChildWithOverclaimingResources extends ResourceClassError {
  def reason = "Can not add child with resources not held by resource class"
}

case class UnknownChild(id: UUID) extends ResourceClassError {
  def reason = s"Unknown child with id: ${id}"
}

case class ChildDoesNotHaveAllResources(resources: IpResourceSet) extends ResourceClassError {
  def reason = s"Child is not entitled to all resources in set: ${resources}"
}