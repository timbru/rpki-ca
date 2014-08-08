package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.NodeSeq

trait View {
  def tab: Tab
  def title: NodeSeq
  def body: NodeSeq
}