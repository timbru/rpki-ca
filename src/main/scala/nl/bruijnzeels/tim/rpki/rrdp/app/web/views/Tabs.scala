package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.NodeSeq
import scala.xml.Text

case class Tab(text: NodeSeq, url: String)

object Tabs {
  val HomeTab = Tab(Text("Home"), "/")
  def visibleTabs = Seq(HomeTab)
}