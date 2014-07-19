package nl.bruijnzeels.tim.rpki.ca.common.cqrs

case class UnknownEventException(event: Event) extends RuntimeException